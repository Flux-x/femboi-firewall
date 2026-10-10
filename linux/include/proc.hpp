#pragma once
// Process execution helper.
//
// Design goals (see audit item 26):
//  - no shell, ever
//  - only an explicit set of absolute-path binaries may be executed
//  - inherited descriptors are close-on-exec
//  - a hung child cannot wedge the caller (bounded wait, then SIGKILL)
//  - stdout/stderr are captured separately and drained concurrently so a
//    child writing more than a pipe buffer cannot deadlock us on stdin writes
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

extern char** environ;

namespace femboifw {

namespace proc_detail {

// Trusted directories an allowlisted binary may live in.
inline bool is_trusted_dir(const std::string& dir) {
    static const char* kDirs[] = {
        "/usr/sbin", "/usr/bin", "/sbin", "/bin",
        "/usr/local/sbin", "/usr/local/bin",
    };
    for (const char* d : kDirs) {
        if (dir == d) return true;
    }
    return false;
}

// Allowlisted executable basenames.
inline bool is_allowed_name(const std::string& base) {
    static const char* kAllowed[] = {
        "nft", "ip", "bpftool", "systemctl",
        "femboi-firewall", "femboi-firewall-xdp",
    };
    for (const char* a : kAllowed) {
        if (base == a) return true;
    }
    return false;
}

// Resolve argv[0] to an absolute, trusted path. Rejects things like
// "/tmp/nft" and bare names that resolve outside the trusted directories.
inline std::string resolve_binary(const std::string& arg0) {
    std::string candidate;
    if (arg0.find('/') != std::string::npos) {
        candidate = arg0;
    } else {
        static const char* kDirs[] = {
            "/usr/sbin", "/usr/bin", "/sbin", "/bin",
            "/usr/local/sbin", "/usr/local/bin",
        };
        for (const char* d : kDirs) {
            const std::string p = std::string(d) + "/" + arg0;
            if (access(p.c_str(), X_OK) == 0) {
                candidate = p;
                break;
            }
        }
        if (candidate.empty()) return {};
    }

    char resolved[4096];
    if (realpath(candidate.c_str(), resolved) == nullptr) return {};

    const std::string full = resolved;
    const size_t slash = full.find_last_of('/');
    const std::string dir = slash == std::string::npos ? std::string() : full.substr(0, slash);
    const std::string base = slash == std::string::npos ? full : full.substr(slash + 1);
    if (!is_allowed_name(base) || !is_trusted_dir(dir)) return {};
    return full;
}

// Minimal, predictable environment for spawned tools.
inline char** minimal_env() {
    static char* kEnv[] = {
        const_cast<char*>("PATH=/usr/sbin:/usr/bin:/sbin:/bin"),
        const_cast<char*>("LC_ALL=C"),
        nullptr,
    };
    return kEnv;
}

inline uint64_t mono_ms() {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

} // namespace proc_detail

// Check allowlisted executable name (kept for callers that only need the
// cheap name test; run_argv enforces the full path check).
inline bool is_allowed_binary(const std::string& arg0) {
    const size_t slash = arg0.find_last_of('/');
    const std::string base = slash == std::string::npos ? arg0 : arg0.substr(slash + 1);
    return proc_detail::is_allowed_name(base);
}

/**
 * @brief Executes an external binary safely without invoking an intermediate shell.
 *
 * This function handles subprocess execution with security guarantees:
 * - Binary paths are strictly checked against a compile-time allowlist.
 * - All pipes are created with O_CLOEXEC to prevent descriptor leaks into children.
 * - posix_spawn is utilized instead of traditional fork/exec to avoid memory footprint spikes.
 * - Standard input is streamed to the child, and standard output/error are captured up to 4 MiB.
 * - A deadline watchdog guarantees that hanging processes are terminated (SIGTERM followed by SIGKILL).
 *
 * @param argv Command vector where argv[0] is the binary name or path.
 * @param out Optional pointer to receive captured standard output.
 * @param err Optional pointer to receive captured standard error or failure message.
 * @param stdin_data Optional payload to pass into the child process standard input.
 * @param timeout_ms Execution deadline in milliseconds; <= 0 disables timeout enforcement.
 * @return true if the process exited with code 0, false otherwise.
 */
inline bool run_argv(const std::vector<std::string>& argv,
                     std::string* out, std::string* err,
                     const std::string& stdin_data = {},
                     int timeout_ms = 10000) {
    // -------------------------------------------------------------------------
    // Step 1: Input validation and binary allowlist verification
    // -------------------------------------------------------------------------
    if (argv.empty()) {
        if (err) *err = "empty argv";
        return false;
    }

    // Resolve binary path against approved executable names.
    const std::string exe = proc_detail::resolve_binary(argv[0]);
    if (exe.empty()) {
        if (err) *err = "refusing to execute non-allowlisted binary: " + argv[0];
        return false;
    }

    // -------------------------------------------------------------------------
    // Step 2: Create pipes for stdin, stdout, and stderr with close-on-exec
    // -------------------------------------------------------------------------
    int in_pipe[2] = {-1, -1};
    int out_pipe[2] = {-1, -1};
    int err_pipe[2] = {-1, -1};

    // Helper lambda to safely close all pipe file descriptors on error.
    auto close_all = [&]() {
        for (int fd : {in_pipe[0], in_pipe[1], out_pipe[0], out_pipe[1], err_pipe[0], err_pipe[1]}) {
            if (fd >= 0) close(fd);
        }
    };

    if (pipe2(in_pipe, O_CLOEXEC) != 0 ||
        pipe2(out_pipe, O_CLOEXEC) != 0 ||
        pipe2(err_pipe, O_CLOEXEC) != 0) {
        if (err) *err = std::string("pipe2: ") + strerror(errno);
        close_all();
        return false;
    }

    // -------------------------------------------------------------------------
    // Step 3: Prepare argument array pointers for posix_spawn
    // -------------------------------------------------------------------------
    std::vector<char*> cargv;
    cargv.reserve(argv.size() + 1);
    cargv.push_back(const_cast<char*>(exe.c_str()));
    for (size_t i = 1; i < argv.size(); ++i) cargv.push_back(const_cast<char*>(argv[i].c_str()));
    cargv.push_back(nullptr);

    // -------------------------------------------------------------------------
    // Step 4: Configure standard file descriptors for the spawned child
    // -------------------------------------------------------------------------
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    // Bind child stdin, stdout, and stderr to pipe endpoints.
    posix_spawn_file_actions_adddup2(&actions, in_pipe[0], STDIN_FILENO);
    posix_spawn_file_actions_adddup2(&actions, out_pipe[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, err_pipe[1], STDERR_FILENO);
    // Close parent endpoints in child context.
    posix_spawn_file_actions_addclose(&actions, in_pipe[1]);
    posix_spawn_file_actions_addclose(&actions, out_pipe[0]);
    posix_spawn_file_actions_addclose(&actions, err_pipe[0]);

    // -------------------------------------------------------------------------
    // Step 5: Launch the child process using posix_spawn
    // -------------------------------------------------------------------------
    pid_t pid = 0;
    const int rc = posix_spawn(&pid, exe.c_str(), &actions, nullptr,
                               cargv.data(), proc_detail::minimal_env());
    posix_spawn_file_actions_destroy(&actions);

    // Close endpoints used exclusively by the child process.
    close(in_pipe[0]);
    close(out_pipe[1]);
    close(err_pipe[1]);

    if (rc != 0) {
        close(in_pipe[1]);
        close(out_pipe[0]);
        close(err_pipe[0]);
        if (err) *err = std::string("spawn ") + exe + ": " + strerror(rc);
        return false;
    }

    // -------------------------------------------------------------------------
    // Step 6: Initialize polling deadline and event tracking buffers
    // -------------------------------------------------------------------------
    const uint64_t deadline = timeout_ms > 0 ? proc_detail::mono_ms() + (uint64_t)timeout_ms : 0;
    size_t stdin_off = 0;
    std::string captured, captured_err;
    bool in_open = true, out_open = true, err_open = true;
    bool timed_out = false;

    // -------------------------------------------------------------------------
    // Step 7: Event multiplexing loop (poll I/O until all descriptors close)
    // -------------------------------------------------------------------------
    while (out_open || err_open || in_open) {
        // Enforce execution timeout limit.
        if (deadline && proc_detail::mono_ms() > deadline) {
            timed_out = true;
            break;
        }

        struct pollfd pfd[3];
        int n = 0;
        int idx_in = -1, idx_out = -1, idx_err = -1;

        // Monitor stdin if there is pending data to transmit to the child.
        if (in_open && stdin_off < stdin_data.size()) {
            idx_in = n;
            pfd[n].fd = in_pipe[1];
            pfd[n].events = POLLOUT;
            pfd[n].revents = 0;
            n++;
        } else if (in_open) {
            // Nothing left to write: close the write end so child receives EOF.
            close(in_pipe[1]);
            in_pipe[1] = -1;
            in_open = false;
            continue;
        }

        // Monitor stdout for available chunks.
        if (out_open) {
            idx_out = n;
            pfd[n].fd = out_pipe[0];
            pfd[n].events = POLLIN;
            pfd[n].revents = 0;
            n++;
        }

        // Monitor stderr for available error output.
        if (err_open) {
            idx_err = n;
            pfd[n].fd = err_pipe[0];
            pfd[n].events = POLLIN;
            pfd[n].revents = 0;
            n++;
        }
        if (n == 0) break;

        // Wait for descriptor activity with a 250ms polling resolution.
        const int pr = poll(pfd, (nfds_t)n, 250);
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (pr == 0) continue;

        // Write chunk to child stdin when ready.
        if (idx_in >= 0 && (pfd[idx_in].revents & POLLOUT)) {
            const ssize_t w = write(in_pipe[1], stdin_data.data() + stdin_off,
                                    stdin_data.size() - stdin_off);
            if (w > 0) stdin_off += (size_t)w;
            else if (w < 0 && errno != EINTR && errno != EAGAIN) {
                close(in_pipe[1]);
                in_pipe[1] = -1;
                in_open = false;
            }
        }

        // Helper lambda to drain descriptor buffer up to 4 MiB capacity.
        auto drain = [&](int fd, std::string* dst, bool* open_flag) {
            char buf[8192];
            for (;;) {
                const ssize_t r = read(fd, buf, sizeof(buf));
                if (r > 0) {
                    if (dst->size() < 4u * 1024 * 1024) dst->append(buf, (size_t)r);
                    continue;
                }
                if (r == 0) {
                    close(fd);
                    *open_flag = false;
                } else if (errno != EINTR && errno != EAGAIN) {
                    close(fd);
                    *open_flag = false;
                }
                break;
            }
        };

        // Drain stdout when data is available.
        if (idx_out >= 0 && (pfd[idx_out].revents & (POLLIN | POLLHUP)))
            drain(out_pipe[0], &captured, &out_open);

        // Drain stderr when data is available.
        if (idx_err >= 0 && (pfd[idx_err].revents & (POLLIN | POLLHUP)))
            drain(err_pipe[0], &captured_err, &err_open);
    }

    // Close remaining open descriptors.
    if (in_pipe[1] >= 0) close(in_pipe[1]);
    if (out_open) close(out_pipe[0]);
    if (err_open) close(err_pipe[0]);

    int status = 0;

    // -------------------------------------------------------------------------
    // Step 8: Handle timeout termination sequence if deadline was exceeded
    // -------------------------------------------------------------------------
    if (timed_out) {
        // First try gentle termination with SIGTERM.
        kill(pid, SIGTERM);
        for (int i = 0; i < 20; ++i) {
            pid_t r = waitpid(pid, &status, WNOHANG);
            if (r == pid) break;
            struct timespec ts{0, 50 * 1000 * 1000};
            nanosleep(&ts, nullptr);
        }
        // If still active, escalate to SIGKILL.
        if (waitpid(pid, &status, WNOHANG) == 0) {
            kill(pid, SIGKILL);
            while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
            }
        }
        if (err) *err = captured_err.empty() ? "command timed out" : captured_err;
        return false;
    }

    // Wait for normal child process exit.
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }

    // -------------------------------------------------------------------------
    // Step 9: Evaluate process exit status and format results
    // -------------------------------------------------------------------------
    const bool ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    if (ok) {
        if (out) *out = captured;
    } else if (err) {
        *err = captured_err.empty() ? (captured.empty() ? "command failed" : captured)
                                    : captured_err;
    }
    return ok;
}

} // namespace femboifw
