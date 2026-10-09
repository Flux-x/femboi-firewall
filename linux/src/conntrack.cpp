// Femboi Firewall — userspace, handshake-gated auto-ban.
//
// Motivation (audit item 2): banning on a single spoofed SYN lets an attacker
// blackhole an arbitrary victim. Here we instead observe kernel conntrack
// events and only escalate a source once it has COMPLETED a TCP handshake
// (conntrack reached ESTABLISHED). A spoofed SYN never completes a handshake,
// so it cannot trigger a ban; a real abuser that opens many connections does.
//
// This is an OPTIONAL build feature (HAVE_CONNTRACK), mirroring the DPI module:
// without libnetfilter-conntrack it compiles to a stub and the daemon falls back
// to the (rate-gated, whitelisted) nftables rules.
#include "fw.hpp"
#include "fw_portable.hpp"

#include <atomic>
#include <cstring>

#ifdef HAVE_CONNTRACK

#include <arpa/inet.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <poll.h>
#include <unistd.h>

#include <cerrno>
#include <unordered_map>

namespace femboifw {

namespace {

// Per-source completed-handshake accounting.
struct CtContext {
    const Config* cfg = nullptr;
    BanCallback* on_ban = nullptr;
    int64_t window_secs = 10;
    uint32_t threshold = 60;
    size_t max_tracked = 65536;
    std::unordered_map<uint32_t, std::pair<int64_t, uint32_t>> handshakes;
};

bool is_protected_port(const Config& cfg, uint16_t dport) {
    for (const auto& p : cfg.ports) {
        if (p.enabled && p.port == dport && p.type != kPortSystem) return true;
    }
    return false;
}

int conntrack_cb(enum nf_conntrack_msg_type type, struct nf_conntrack* ct, void* data) {
    auto* ctx = static_cast<CtContext*>(data);
    if (type != NFCT_T_NEW && type != NFCT_T_UPDATE) return NFCT_CB_CONTINUE;

    // TCP flows only.
    if (nfct_get_attr_u8(ct, ATTR_L4PROTO) != IPPROTO_TCP) return NFCT_CB_CONTINUE;

    // Only flows destined to a protected (game/web) port.
    const uint16_t dport = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST);
    if (!is_protected_port(*ctx->cfg, dport)) return NFCT_CB_CONTINUE;

    // The handshake must have completed — this is the whole point.
    if (nfct_get_attr_u8(ct, ATTR_TCP_STATE) != TCP_CONNTRACK_ESTABLISHED)
        return NFCT_CB_CONTINUE;

    const uint32_t src = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC);
    if (is_local_or_loopback_ipv4(src)) return NFCT_CB_CONTINUE;

    const int64_t now = NowEpoch();
    auto& slot = ctx->handshakes[src];
    if (slot.first == 0 || now - slot.first >= ctx->window_secs) {
        slot.first = now;
        slot.second = 0;
    }
    if (++slot.second > ctx->threshold) {
        if (ctx->on_ban && (*ctx->on_ban)(src, "conntrack-handshake-flood")) {
            ctx->handshakes.erase(src);
            Logf(3, "conntrack: banned %s (handshake flood)", FormatIp(src).c_str());
        }
    }

    // Bound memory under a connection flood.
    if (ctx->handshakes.size() > ctx->max_tracked) ctx->handshakes.clear();
    return NFCT_CB_CONTINUE;
}

} // namespace

// Report whether conntrack events are usable at runtime.
bool ConntrackAvailable() {
    return access("/proc/net/nf_conntrack", F_OK) == 0 ||
           access("/proc/net/ip_conntrack", F_OK) == 0;
}

// Subscribe to conntrack events and escalate established-flow floods to bans.
void RunConntrackLoop(std::shared_ptr<const Config> cfg, BanCallback on_ban,
                      std::atomic<bool>& stop) {
    if (!cfg) return;

    struct nfct_handle* h =
        nfct_open(CONNTRACK, NF_NETLINK_CONNTRACK_NEW | NF_NETLINK_CONNTRACK_UPDATE);
    if (!h) {
        Logf(0, "conntrack: nfct_open failed (need root/CAP_NET_ADMIN) — handshake auto-ban disabled");
        return;
    }

    CtContext ctx;
    ctx.cfg = cfg.get();
    ctx.on_ban = &on_ban;
    // A source opening more than ~1/10th of its packet budget as new TCP
    // handshakes per window is treated as abusive.
    ctx.threshold = cfg->per_ip_pps > 200 ? cfg->per_ip_pps / 10 : 60;

    if (nfct_callback_register(h, NFCT_T_ALL, conntrack_cb, &ctx) < 0) {
        Logf(0, "conntrack: callback register failed — disabled");
        nfct_close(h);
        return;
    }

    Logf(2, "conntrack: handshake-gated auto-ban active (threshold %u/%llds per source)",
         ctx.threshold, (long long)ctx.window_secs);

    const int fd = nfct_fd(h);
    while (!stop.load(std::memory_order_relaxed)) {
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        const int pr = poll(&pfd, 1, 500);
        if (pr < 0) {
            if (errno == EINTR) continue;
            Logf(1, "conntrack: poll failed: %s", strerror(errno));
            break;
        }
        if (pr == 0) continue;
        if (nfct_catch(h) < 0) {
            if (errno == EINTR) continue;
            Logf(1, "conntrack: catch failed: %s", strerror(errno));
            break;
        }
    }

    nfct_close(h);
    Logf(2, "conntrack: stopped");
}

} // namespace femboifw

#else // !HAVE_CONNTRACK

namespace femboifw {

// Return false when compiled without libnetfilter-conntrack.
bool ConntrackAvailable() { return false; }

// Stub function when conntrack support is unavailable.
void RunConntrackLoop(std::shared_ptr<const Config>, BanCallback, std::atomic<bool>&) {
    Logf(1, "handshake auto-ban requested but this build has no conntrack support.");
}

} // namespace femboifw

#endif // HAVE_CONNTRACK
