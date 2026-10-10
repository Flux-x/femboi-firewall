// Femboi Firewall daemon control socket (see fw_ctl.hpp).
#include "fw_ctl.hpp"
#include "fw.hpp"

#include <grp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <map>
#include <sstream>
#include <vector>

namespace femboifw {

namespace {

// Escape a string for inclusion in a JSON double-quoted value.
std::string JsonEscape(const std::string& in) {
    std::string out;
    out.reserve(in.size() + 8);
    for (unsigned char c : in) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += (char)c;
                }
        }
    }
    return out;
}

std::string ErrJson(const std::string& msg) {
    return "{\"ok\":false,\"error\":\"" + JsonEscape(msg) + "\"}";
}

// Parse "<verb> <rest>" returning the verb and the exact remainder string.
void SplitVerb(const std::string& line, std::string* verb, std::string* rest) {
    size_t i = 0;
    while (i < line.size() && isspace((unsigned char)line[i])) i++;
    const size_t start = i;
    while (i < line.size() && !isspace((unsigned char)line[i])) i++;
    *verb = line.substr(start, i - start);
    while (i < line.size() && isspace((unsigned char)line[i])) i++;
    *rest = line.substr(i);
}

// Parse a ttl token: "permanent" -> 0, otherwise a positive integer (0 on error).
bool ParseTtl(const std::string& tok, long long* out) {
    if (tok == "permanent") { *out = 0; return true; }
    char* end = nullptr;
    long long v = strtoll(tok.c_str(), &end, 10);
    if (end == tok.c_str() || *end != '\0' || v < 0) return false;
    *out = v;
    return true;
}

// Read one newline-terminated request from a connection (bounded).
std::string ReadRequestLine(int fd) {
    std::string buf;
    char chunk[512];
    for (;;) {
        const ssize_t n = ::read(fd, chunk, sizeof(chunk));
        if (n < 0) {
            if (errno == EINTR) continue;
            return {};
        }
        if (n == 0) break;
        buf.append(chunk, (size_t)n);
        if (buf.find('\n') != std::string::npos) break;
        if (buf.size() > 8192u) break;  // bound a hostile client
    }
    const size_t nl = buf.find('\n');
    if (nl != std::string::npos) buf.resize(nl);
    while (!buf.empty() && (buf.back() == '\r')) buf.pop_back();
    return buf;
}

// Monotonic clock in nanoseconds (drives the rate limiters).
uint64_t MonoNs() {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

// Read the peer's supplementary groups from /proc/<pid>/status. SO_PEERCRED
// reports only the primary gid, so a user added with `usermod -aG femboi`
// (a supplementary group) would otherwise be rejected.
bool PeerHasGroup(pid_t pid, gid_t gid) {
    std::ifstream in("/proc/" + std::to_string((long long)pid) + "/status");
    if (!in) return false;
    std::string line;
    while (std::getline(in, line)) {
        if (line.rfind("Groups:", 0) != 0) continue;
        std::istringstream ss(line.substr(7));
        unsigned long v = 0;
        while (ss >> v) {
            if ((gid_t)v == gid) return true;
        }
        return false;
    }
    return false;
}

// Authorization decision for a peer, given the resolved `femboi` gid.
bool PeerAllowed(const struct ucred& cred, gid_t femboi_gid, bool have_group) {
    if (cred.uid == 0 || cred.uid == ::geteuid()) return true;
    if (!have_group) return false;
    if (cred.gid == femboi_gid) return true;
    return PeerHasGroup(cred.pid, femboi_gid);
}

} // namespace

std::string HandleCtlLine(const std::string& line, const CtlHandlers& h) {
    std::string verb, rest;
    SplitVerb(line, &verb, &rest);

    if (verb.empty()) return ErrJson("empty request");

    if (verb == "status") {
        if (!h.status) return ErrJson("status unavailable");
        return h.status();
    }
    if (verb == "stats") {
        if (!h.stats) return ErrJson("stats unavailable");
        return h.stats();
    }
    if (verb == "list") {
        if (!h.list) return ErrJson("list unavailable");
        return h.list();
    }
    if (verb == "ban") {
        if (!h.ban) return ErrJson("ban unavailable");
        std::string ip;
        std::string reason;
        long long ttl = 0;
        // rest = "<ip> [ttl] [reason...]"
        std::string tmp = rest;
        size_t i = 0;
        while (i < tmp.size() && isspace((unsigned char)tmp[i])) i++;
        size_t start = i;
        while (i < tmp.size() && !isspace((unsigned char)tmp[i])) i++;
        ip = tmp.substr(start, i - start);
        if (ip.empty()) return ErrJson("ban needs an address");
        while (i < tmp.size() && isspace((unsigned char)tmp[i])) i++;
        // Optional numeric/permanent ttl only if the next token is one.
        if (i < tmp.size()) {
            size_t ts = i;
            while (i < tmp.size() && !isspace((unsigned char)tmp[i])) i++;
            const std::string tok = tmp.substr(ts, i - ts);
            long long parsed = 0;
            if (ParseTtl(tok, &parsed)) {
                ttl = parsed;
                while (i < tmp.size() && isspace((unsigned char)tmp[i])) i++;
                reason = tmp.substr(i);
            } else {
                reason = tmp.substr(ts);
            }
        }
        if (reason.empty()) reason = "manual";
        return h.ban(ip, ttl, reason);
    }
    if (verb == "unban") {
        if (!h.unban) return ErrJson("unban unavailable");
        std::string ip;
        size_t i = 0;
        while (i < rest.size() && isspace((unsigned char)rest[i])) i++;
        size_t start = i;
        while (i < rest.size() && !isspace((unsigned char)rest[i])) i++;
        ip = rest.substr(start, i - start);
        if (ip.empty()) return ErrJson("unban needs an address");
        return h.unban(ip);
    }
    if (verb == "set") {
        if (!h.set) return ErrJson("set unavailable");
        std::string key, value;
        size_t i = 0;
        while (i < rest.size() && isspace((unsigned char)rest[i])) i++;
        size_t start = i;
        while (i < rest.size() && !isspace((unsigned char)rest[i])) i++;
        key = rest.substr(start, i - start);
        while (i < rest.size() && isspace((unsigned char)rest[i])) i++;
        value = rest.substr(i);
        if (key.empty()) return ErrJson("set needs a key");
        if (value.empty()) return ErrJson("set needs a value");
        return h.set(key, value);
    }
    return ErrJson("unknown verb: " + verb);
}

std::string CtlClientCall(const std::string& sock_path, const std::string& request) {
    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return {};

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (sock_path.size() >= sizeof(addr.sun_path)) {
        ::close(fd);
        return {};
    }
    // strncpy with explicit NUL: sun_path is not guaranteed terminated otherwise.
    memcpy(addr.sun_path, sock_path.c_str(), sock_path.size());
    addr.sun_path[sock_path.size()] = '\0';

    if (::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return {};
    }

    std::string out = request;
    out.push_back('\n');
    size_t off = 0;
    while (off < out.size()) {
        const ssize_t n = ::write(fd, out.data() + off, out.size() - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            return {};
        }
        off += (size_t)n;
    }

    std::string resp;
    char chunk[512];
    for (;;) {
        const ssize_t n = ::read(fd, chunk, sizeof(chunk));
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        resp.append(chunk, (size_t)n);
        if (resp.find('\n') != std::string::npos) break;
        if (resp.size() > 65536u) break;
    }
    ::close(fd);

    const size_t nl = resp.find('\n');
    if (nl != std::string::npos) resp.resize(nl);
    while (!resp.empty() && resp.back() == '\r') resp.pop_back();
    return resp;
}

void CtlRateLimiter::Configure(double rate, double burst_tokens) {
    rate_per_sec = rate > 0.0 ? rate : 1.0;
    burst = burst_tokens > 0.0 ? burst_tokens : 1.0;
    tokens = burst;
    last_ns = 0;
}

bool CtlRateLimiter::Allow(uint64_t now_ns) {
    if (last_ns == 0) last_ns = now_ns;
    const int64_t delta = (int64_t)(now_ns - last_ns);
    if (delta > 0) {
        tokens += (double)delta / 1e9 * rate_per_sec;
        if (tokens > burst) tokens = burst;
        last_ns = now_ns;
    }
    if (tokens >= 1.0) {
        tokens -= 1.0;
        return true;
    }
    return false;
}

void RunCtlServer(const std::string& sock_path, const CtlHandlers& handlers,
                  std::atomic<bool>& stop) {
    const size_t slash = sock_path.find_last_of('/');
    if (slash != std::string::npos && slash > 0) {
        const std::string dir = sock_path.substr(0, slash);
        ::mkdir(dir.c_str(), 0750);
    }

    ::unlink(sock_path.c_str());

    const int sfd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sfd < 0) {
        Logf(0, "ctl: socket() failed: %s", strerror(errno));
        return;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (sock_path.size() >= sizeof(addr.sun_path)) {
        Logf(0, "ctl: socket path too long: %s", sock_path.c_str());
        ::close(sfd);
        return;
    }
    memcpy(addr.sun_path, sock_path.c_str(), sock_path.size());
    addr.sun_path[sock_path.size()] = '\0';

    // 0077 umask so the socket is not world-accessible between bind and chmod.
    const mode_t old_umask = ::umask(0077);
    const int brc = ::bind(sfd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
    ::umask(old_umask);
    if (brc != 0) {
        Logf(0, "ctl: bind %s failed: %s", sock_path.c_str(), strerror(errno));
        ::close(sfd);
        return;
    }
    ::chmod(sock_path.c_str(), 0660);
    // Group ownership lets an unprivileged GUI member of `femboi` connect while
    // keeping the socket off-world. Absent the group the socket stays root:root.
    gid_t femboi_gid = 0;
    bool have_group = false;
    if (struct group* g = ::getgrnam("femboi")) {
        femboi_gid = g->gr_gid;
        have_group = true;
        ::chown(sock_path.c_str(), 0, femboi_gid);
    }

    if (::listen(sfd, 16) != 0) {
        Logf(0, "ctl: listen failed: %s", strerror(errno));
        ::close(sfd);
        ::unlink(sock_path.c_str());
        return;
    }

    Logf(2, "ctl: control socket listening at %s", sock_path.c_str());

    // Global + per-uid token buckets bound the request rate so a runaway or
    // hostile local client cannot spin the daemon.
    CtlRateLimiter global_rl;
    global_rl.Configure(100.0, 100.0);
    std::map<uid_t, CtlRateLimiter> per_uid;

    while (!stop.load(std::memory_order_relaxed)) {
        struct pollfd pfd;
        pfd.fd = sfd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        const int pr = ::poll(&pfd, 1, 500);
        if (pr < 0) {
            if (errno == EINTR) continue;
            Logf(1, "ctl: poll failed: %s", strerror(errno));
            break;
        }
        if (pr == 0) continue;
        if (!(pfd.revents & POLLIN)) continue;

        const int cfd = ::accept4(sfd, nullptr, nullptr, SOCK_CLOEXEC);
        if (cfd < 0) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            Logf(1, "ctl: accept failed: %s", strerror(errno));
            continue;
        }

        // Authorize via kernel-provided peer credentials (unspoofable).
        struct ucred cred;
        socklen_t clen = sizeof(cred);
        if (::getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cred, &clen) != 0) {
            Logf(1, "ctl: cannot read peer creds: %s", strerror(errno));
            ::close(cfd);
            continue;
        }
        if (!PeerAllowed(cred, femboi_gid, have_group)) {
            Logf(1, "ctl: refusing request from uid %u gid %u",
                 (unsigned)cred.uid, (unsigned)cred.gid);
            const std::string deny = ErrJson("permission denied") + "\n";
            (void)!::write(cfd, deny.data(), deny.size());
            ::close(cfd);
            continue;
        }

        const uint64_t now = MonoNs();
        CtlRateLimiter& rl = per_uid[cred.uid];
        if (rl.last_ns == 0) rl.Configure(20.0, 40.0);
        if (!global_rl.Allow(now) || !rl.Allow(now)) {
            Logf(1, "ctl: rate-limited uid=%u", (unsigned)cred.uid);
            const std::string deny = ErrJson("rate limited") + "\n";
            (void)!::write(cfd, deny.data(), deny.size());
            ::close(cfd);
            continue;
        }

        const std::string line = ReadRequestLine(cfd);
        // Per-request audit log. Length is bounded so a hostile client cannot
        // inflate the log via an oversized request line.
        Logf(2, "ctl: uid=%u pid=%u cmd=%.200s", (unsigned)cred.uid,
             (unsigned)cred.pid, line.c_str());

        std::string resp = line.empty() ? ErrJson("empty request")
                                        : HandleCtlLine(line, handlers);
        resp.push_back('\n');
        size_t off = 0;
        while (off < resp.size()) {
            const ssize_t n = ::write(cfd, resp.data() + off, resp.size() - off);
            if (n < 0) {
                if (errno == EINTR) continue;
                break;
            }
            off += (size_t)n;
        }
        ::close(cfd);
    }

    ::close(sfd);
    ::unlink(sock_path.c_str());
    Logf(2, "ctl: control socket stopped");
}

} // namespace femboifw
