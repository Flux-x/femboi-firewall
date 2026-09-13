#pragma once
// Process execution helper
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <string>
#include <vector>

extern char** environ;

namespace femboifw {

// Check allowlisted executable name
inline bool is_allowed_binary(const std::string& arg0) {
    size_t slash = arg0.find_last_of('/');
    const std::string base = slash == std::string::npos ? arg0 : arg0.substr(slash + 1);

    static const char* kAllowed[] = {"nft", "ip", "bpftool", "systemctl", "femboi-firewall", "femboi-firewall-xdp"};
    for (const char* a : kAllowed) {
        if (base == a) return true;
    }
    return false;
}

// Spawn process safely without shell
inline bool run_argv(const std::vector<std::string>& argv,
                     std::string* out, std::string* err,
                     const std::string& stdin_data = {}) {
    if (argv.empty()) {
        if (err) *err = "empty argv";
        return false;
    }
    if (!is_allowed_binary(argv[0])) {
        if (err) *err = "refusing to execute non-allowlisted binary: " + argv[0];
        return false;
    }

    int in_pipe[2] = {-1, -1};
    int out_pipe[2] = {-1, -1};
    if (pipe(in_pipe) != 0) {
        if (err) *err = std::string("pipe: ") + strerror(errno);
        return false;
    }
    if (pipe(out_pipe) != 0) {
        close(in_pipe[0]);
        close(in_pipe[1]);
        if (err) *err = std::string("pipe: ") + strerror(errno);
        return false;
    }

    std::vector<char*> cargv;
    cargv.reserve(argv.size() + 1);
    for (const auto& a : argv) cargv.push_back(const_cast<char*>(a.c_str()));
    cargv.push_back(nullptr);

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, in_pipe[0], STDIN_FILENO);
    posix_spawn_file_actions_adddup2(&actions, out_pipe[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, out_pipe[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(&actions, in_pipe[1]);
    posix_spawn_file_actions_addclose(&actions, out_pipe[0]);

    pid_t pid = 0;
    const int rc = posix_spawnp(&pid, cargv[0], &actions, nullptr,
                                cargv.data(), environ);
    posix_spawn_file_actions_destroy(&actions);

    close(in_pipe[0]);
    close(out_pipe[1]);

    if (rc != 0) {
        close(in_pipe[1]);
        close(out_pipe[0]);
        if (err) *err = std::string("spawn ") + argv[0] + ": " + strerror(rc);
        return false;
    }

    if (!stdin_data.empty()) {
        size_t off = 0;
        while (off < stdin_data.size()) {
            const ssize_t n =
                write(in_pipe[1], stdin_data.data() + off, stdin_data.size() - off);
            if (n < 0) {
                if (errno == EINTR) continue;
                break;
            }
            if (n == 0) break;
            off += (size_t)n;
        }
    }
    close(in_pipe[1]);

    std::string captured;
    char buf[4096];
    ssize_t n;
    while ((n = read(out_pipe[0], buf, sizeof(buf))) > 0) {
        captured.append(buf, (size_t)n);
        if (captured.size() > 4u * 1024 * 1024) break;
    }
    close(out_pipe[0]);

    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }

    const bool ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    if (ok) {
        if (out) *out = captured;
    } else if (err) {
        *err = captured.empty() ? "command failed" : captured;
    }
    return ok;
}

} // namespace femboifw
