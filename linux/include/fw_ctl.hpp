#pragma once
// Femboi Firewall daemon control socket.
//
// A Unix-domain socket at /run/femboi/ctl.sock that exposes status, stats, ban,
// unban and config-set to local clients (CLI and GUI). The daemon is the ONLY
// component that touches nftables/XDP and the config, so the GUI no longer needs
// to shell out to `nft`/`conntrack` or write /etc/femboi directly.
//
// Authorization: every connection is checked with SO_PEERCRED; only uid 0 or the
// daemon's own uid (or a member of the socket's group) may issue commands. There
// is no TCP listener.
#include <atomic>
#include <functional>
#include <string>

namespace femboifw {

inline constexpr const char* kCtlSockPath = "/run/femboi/ctl.sock";

// Callbacks provided by the daemon. Each returns a one-line JSON string.
struct CtlHandlers {
    std::function<std::string()> status;
    std::function<std::string()> stats;
    std::function<std::string()> list;
    std::function<std::string(const std::string& ip, long long ttl,
                              const std::string& reason)> ban;
    std::function<std::string(const std::string& ip)> unban;
    // Validate + persist a single config key, then trigger a live reload.
    std::function<std::string(const std::string& key,
                              const std::string& value)> set;
};

// Serve one newline-terminated request line (already authorized).
// Protocol: "<verb> [args...]" -> one-line JSON response.
std::string HandleCtlLine(const std::string& line, const CtlHandlers& h);

// Client side: send one request, return the response line ("" on any failure).
std::string CtlClientCall(const std::string& sock_path, const std::string& request);

// Server loop. Binds sock_path (mode 0660), accepts connections and serves them
// until `stop` is set. Blocking; run it on its own thread. The parent directory
// is created (mode 0750) if missing.
void RunCtlServer(const std::string& sock_path, CtlHandlers handlers,
                  std::atomic<bool>& stop);

} // namespace femboifw
