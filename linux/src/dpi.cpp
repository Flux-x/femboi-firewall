// Femboi Firewall DPI inspection
#include "fw.hpp"
#include "fw_l7_http.hpp"
#include "fw_portable.hpp"

#ifdef HAVE_NFQUEUE

#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstring>

namespace femboifw {

namespace {

struct DpiContext {
    Config* cfg = nullptr;
    Counters* counters = nullptr;
    std::atomic<uint64_t>* drops = nullptr;
};

// Read big endian 16-bit integer
uint16_t read_be16(const unsigned char* p) { return (uint16_t)((p[0] << 8) | p[1]); }

// Inspect single packet payload
bool inspect(const DpiContext& ctx, const unsigned char* pkt, unsigned len,
             uint16_t* out_sport, uint16_t* out_dport, uint8_t* out_proto,
             uint32_t* out_src_nbo, std::string* out_reason) {
    if (len < 20) return false;

    const struct iphdr* ip = reinterpret_cast<const struct iphdr*>(pkt);
    const unsigned ihl = ip->ihl * 4u;
    if (ip->version != 4 || ihl < 20 || len < ihl + 8) return false;

    *out_src_nbo = ip->saddr;
    *out_proto = ip->protocol;
    const unsigned char* l4 = pkt + ihl;
    const unsigned l4len = len - ihl;

    if (ip->protocol == IPPROTO_TCP) {
        if (l4len < 20) return false;
        const struct tcphdr* tcp = reinterpret_cast<const struct tcphdr*>(l4);
        *out_sport = read_be16(l4 + 0);
        *out_dport = read_be16(l4 + 2);
        const unsigned thl = tcp->doff * 4u;
        if (thl < 20 || l4len <= thl) return false;

        const unsigned char* payload = l4 + thl;
        const unsigned plen = l4len - thl;

        const uint16_t dport = *out_dport;
        for (const auto& slot : ctx.cfg->ports) {
            if (!slot.enabled || slot.type != kPortWeb || slot.port != dport) continue;

            const L7Result r = (dport == 443 || dport == 8443 || dport == 9443)
                                   ? l7_inspect_tls(payload, plen)
                                   : l7_inspect_http(payload, plen);
            switch (r) {
                case L7_SCANNER_PROBE:
                    *out_reason = "http-scanner-probe";
                    return true;
                case L7_EXPLOIT_PAYLOAD:
                    *out_reason = "http-exploit-payload";
                    return true;
                case L7_TLS_INVALID:
                    *out_reason = "plaintext-on-tls-port";
                    return true;
                case L7_SLOWLORIS_FRAGMENT:
                    if (plen > 0 && plen < 4) {
                        *out_reason = "slowloris-fragment";
                        return true;
                    }
                    return false;
                default:
                    return false;
            }
        }
        return false;
    }

    if (ip->protocol == IPPROTO_UDP) {
        if (l4len < 8) return false;
        *out_sport = read_be16(l4 + 0);
        *out_dport = read_be16(l4 + 2);
        const unsigned char* payload = l4 + 8;
        const unsigned plen = l4len - 8;
        if (plen == 0) return false;

        const uint16_t dport = *out_dport;
        for (const auto& slot : ctx.cfg->ports) {
            if (!slot.enabled || slot.type != kPortGame || slot.port != dport) continue;

            const PacketType t = classify_packet_type(payload, plen);
            if (t == PKT_EXPLOIT) {
                *out_reason = "srcds-exploit";
                return true;
            }
            if (t == PKT_INVALID) {
                *out_reason = "srcds-malformed";
                return true;
            }
        }
        return false;
    }

    return false;
}

// Queue callback handler
int queue_cb(struct nfq_q_handle* qh, struct nfgenmsg* /*nfmsg*/,
             struct nfq_data* nfa, void* data) {
    auto* ctx = static_cast<DpiContext*>(data);

    struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa);
    const uint32_t id = ph ? ntohl(ph->packet_id) : 0;

    unsigned char* payload = nullptr;
    const int len = nfq_get_payload(nfa, &payload);
    if (len <= 0 || !payload) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
    }

    uint16_t sport = 0, dport = 0;
    uint8_t proto = 0;
    uint32_t src_nbo = 0;
    std::string reason;

    bool drop = false;
    try {
        drop = inspect(*ctx, payload, (unsigned)len, &sport, &dport, &proto,
                       &src_nbo, &reason);
    } catch (...) {
        drop = false;
    }

    if (!drop) {
        ctx->counters->processed.fetch_add(1, std::memory_order_relaxed);
        ctx->counters->passed.fetch_add(1, std::memory_order_relaxed);
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
    }

    ctx->counters->processed.fetch_add(1, std::memory_order_relaxed);
    if (reason.rfind("srcds", 0) == 0) {
        ctx->counters->blocked_exploit.fetch_add(1, std::memory_order_relaxed);
    } else {
        ctx->counters->blocked_tcp_payload.fetch_add(1, std::memory_order_relaxed);
    }
    ctx->drops->fetch_add(1, std::memory_order_relaxed);

    Logf(3, "DPI drop %s:%u -> :%u proto=%u (%s)",
         FormatIp(src_nbo).c_str(), sport, dport, proto, reason.c_str());

    return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);
}

} // namespace

// Run blocking nfqueue packet loop
void RunDpiLoop(Config& cfg, Counters& counters, std::atomic<uint64_t>& drops,
                std::atomic<bool>& stop, uint16_t queue_num) {
    struct nfq_handle* h = nfq_open();
    if (!h) {
        Logf(0, "DPI: nfq_open failed (need root) — DPI disabled");
        return;
    }
    if (nfq_unbind_pf(h, AF_INET) < 0 || nfq_bind_pf(h, AF_INET) < 0) {
        Logf(0, "DPI: cannot bind AF_INET handler — DPI disabled");
        nfq_close(h);
        return;
    }

    DpiContext ctx;
    ctx.cfg = &cfg;
    ctx.counters = &counters;
    ctx.drops = &drops;

    struct nfq_q_handle* qh = nfq_create_queue(h, queue_num, &queue_cb, &ctx);
    if (!qh) {
        Logf(0, "DPI: cannot create queue %u — DPI disabled", queue_num);
        nfq_close(h);
        return;
    }
    nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);
    nfq_set_queue_maxlen(qh, 4096);

    Logf(2, "DPI: listening on nfqueue %u", queue_num);

    const int fd = nfq_fd(h);
    std::vector<unsigned char> buf(0xffff + 0x100);

    while (!stop.load(std::memory_order_relaxed)) {
        const ssize_t n = recv(fd, buf.data(), buf.size(), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == ENOBUFS) {
                Logf(1, "DPI: nfqueue overrun (ENOBUFS) — kernel dropped packets");
                continue;
            }
            Logf(1, "DPI: recv failed: %s", strerror(errno));
            break;
        }
        if (n == 0) continue;
        nfq_handle_packet(h, reinterpret_cast<char*>(buf.data()), (int)n);
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    Logf(2, "DPI: stopped");
}

} // namespace femboifw

#else // !HAVE_NFQUEUE

namespace femboifw {

// Return false when compiled without nfqueue
bool DpiAvailable() { return false; }

// Stub function when nfqueue unavailable
void RunDpiLoop(Config&, Counters&, std::atomic<uint64_t>&, std::atomic<bool>&,
                uint16_t) {
    Logf(1, "DPI requested but this build has no nfqueue support.");
}

} // namespace femboifw

#endif // HAVE_NFQUEUE
