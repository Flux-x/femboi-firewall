// Femboi Firewall nftables enforcement
#include "fw.hpp"
#include "fw_portable.hpp"
#include "proc.hpp"

#include <arpa/inet.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <sstream>

namespace femboifw {

namespace {

// Validate and canonicalise a whitelist entry (single address or CIDR).
// Returns an empty string for malformed input so it is skipped rather than
// being injected into the ruleset script.
std::string FormatIpRange(const std::string& raw) {
    std::string s = raw;
    size_t b = s.find_first_not_of(" \t\r\n");
    size_t e = s.find_last_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    s = s.substr(b, e - b + 1);

    const size_t slash = s.find('/');
    const std::string ip_part = slash == std::string::npos ? s : s.substr(0, slash);
    struct in_addr a;
    if (inet_pton(AF_INET, ip_part.c_str(), &a) != 1) return {};
    if (slash == std::string::npos) return ip_part;

    char* end = nullptr;
    const long prefix = strtol(s.c_str() + slash + 1, &end, 10);
    if (end == s.c_str() + slash + 1 || prefix < 0 || prefix > 32) return {};
    return ip_part + "/" + std::to_string(prefix);
}

// Format IP address range string
std::string cidr_or_range(uint32_t start_host, uint32_t end_host) {
    char buf[64];
    struct in_addr a, b;
    a.s_addr = htonl(start_host);
    b.s_addr = htonl(end_host);
    char sa[INET_ADDRSTRLEN], sb[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a, sa, sizeof(sa));
    inet_ntop(AF_INET, &b, sb, sizeof(sb));
    if (start_host == end_host) {
        snprintf(buf, sizeof(buf), "%s", sa);
    } else {
        snprintf(buf, sizeof(buf), "%s-%s", sa, sb);
    }
    return buf;
}

} // namespace

// Check if nft command is installed
bool Nft::Available() {
    return access("/usr/sbin/nft", X_OK) == 0 ||
           access("/sbin/nft", X_OK) == 0 ||
           access("/usr/bin/nft", X_OK) == 0;
}

// Execute nft command with arguments
bool Nft::Run(const std::vector<std::string>& args, std::string* out, std::string* err) {
    std::vector<std::string> argv{"nft"};
    argv.insert(argv.end(), args.begin(), args.end());
    return run_argv(argv, out, err);
}

// Apply nft ruleset script atomically
bool Nft::RunScript(const std::string& script, std::string* out, std::string* err) {
    std::vector<std::string> argv{"nft", "-f", "-"};
    return run_argv(argv, out, err, script);
}

// Build the complete nftables script for the given config without applying it.
// Exposed so tooling/CI can validate the generated ruleset with `nft -c -f -`.
std::string Nft::BuildScript(const Config& cfg) {
    std::ostringstream s;

    // Flush prior table state
    s << "add table " << kFamily << " " << kTable << "\n";
    s << "delete table " << kFamily << " " << kTable << "\n";

    s << "table " << kFamily << " " << kTable << " {\n";

    // Trusted source set: never rate-limited, never auto-banned.
    // Populated by the daemon (operator + explicitly configured admin IPs).
    s << "  set whitelist {\n"
         "    type ipv4_addr\n"
         "    flags interval\n"
         "  }\n";

    // Dynamic drop sets
    s << "  set banned {\n"
         "    type ipv4_addr\n"
         "    flags dynamic, timeout\n"
         "    size 262144\n"
         "    timeout 1h\n"
         "  }\n";
    s << "  set banned_ports {\n"
         "    type ipv4_addr . inet_service\n"
         "    flags dynamic, timeout\n"
         "  }\n";
    s << "  set geo_blocked {\n"
         "    type ipv4_addr\n"
         "    flags interval\n"
         "  }\n";
    s << "  set geo_ratelimit {\n"
         "    type ipv4_addr\n"
         "    flags interval\n"
         "  }\n";
    s << "  set dc_blocked {\n"
         "    type ipv4_addr\n"
         "    flags interval\n"
         "  }\n";

    // Prerouting raw hook.
    // NOTE: priority -310 runs before conntrack, so only pure L3 matches are
    // valid here. Geo/ASN filtering (which must be scoped with `ct state new`
    // so that replies to the server's own outbound connections survive) lives
    // in the input chain instead.
    s << "  chain prerouting {\n"
         "    type filter hook prerouting priority -310; policy accept;\n"
         "    meta nfproto ipv4 ip saddr @banned drop\n"
         "    meta nfproto ipv4 ip saddr . th dport @banned_ports drop\n"
         "  }\n";

    // Input packet filter chain.
    // Ordering contract (see docs): hard drops -> sanity -> L7/DPI -> per-flow
    // meters -> `ct state established,related accept` -> new-connection policy.
    // Established traffic MUST traverse the meters/DPI, otherwise UDP flood
    // accounting and TCP payload inspection are dead code.
    s << "  chain input {\n"
         "    type filter hook input priority -10; policy accept;\n"
         "\n"
         "    counter comment \"traffic_all\"\n"
         "\n"
         "    iif lo accept\n"
         "    ip saddr 127.0.0.0/8 accept\n"
         "\n"
         "    iifname \"tailscale0\" accept\n"
         "\n"
         // IPv6 is currently unmanaged by the enforcement sets (ipv4_addr).
         // Pass it (with ICMPv6 control traffic) rather than blackholing NDP/RA.
         "    meta nfproto ipv6 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert, packet-too-big } accept\n"
         "    meta nfproto ipv6 counter accept comment \"ipv6-unmanaged\"\n"
         "\n"
         // Trusted sources bypass every limit and auto-ban path.
         "    meta nfproto ipv4 ip saddr @whitelist counter accept comment \"whitelist\"\n"
         "\n"
         "    ip saddr @banned counter drop\n"
         "    ip saddr . th dport @banned_ports counter drop\n"
         // Geo/ASN filtering applies to NEW flows only, so replies to the
         // server's own outbound connections are never dropped.
         "    meta nfproto ipv4 ct state new ip saddr @geo_blocked counter drop\n"
         "    meta nfproto ipv4 ct state new ip saddr @dc_blocked counter drop\n"
         "\n"
         "    ip hdrlength > 5 counter drop\n"
         "    iifname != \"lo\" ip saddr 127.0.0.0/8 counter drop\n"
         "    ip saddr 0.0.0.0/8 counter drop\n"
         "    ip saddr 224.0.0.0/4 counter drop\n"
         "    ip saddr 240.0.0.0/4 counter drop\n"
         "\n"
         "    ct state invalid counter drop\n"
         "\n"
         "    pkttype { broadcast, multicast } counter drop\n"
         "\n"
         // Sensitive management ports: never expose, and auto-ban only on a
         // fresh SYN (ct state new), behind the whitelist. A spoofed SYN can
         // still trigger a ban of a third-party address; operators who expose
         // these ports must populate `whitelist`. Kept conservative: no ban
         // storm from a single packet thanks to the meter.
         "    tcp dport { 21, 23, 25, 110, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200 } ct state new meter mgmt_sweep { ip saddr limit rate over 4/minute burst 8 packets } log prefix \"femboifw mgmt-sweep \" update @banned { ip saddr timeout 1h } counter drop\n"
         "    tcp dport { 21, 23, 25, 110, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200 } counter drop\n"
         "    udp dport { 137, 138, 139, 1434, 1900, 5353 } counter drop\n"
         "\n"
         "    udp sport { 17, 19, 53, 69, 111, 123, 137, 138, 161, 389, 520, 1434, 1900, 3283, 3478, 3702, 5093, 5351, 5353, 11211, 27010-27014 } ct state new counter drop\n"
         "\n"
         "    tcp flags & (fin|syn|rst|ack) == 0 counter drop\n"
         "    tcp flags & (fin|syn) == (fin|syn) counter drop\n"
         "    tcp flags & (syn|rst) == (syn|rst) counter drop\n"
         "    tcp flags & (fin|rst) == (fin|rst) counter drop\n"
         "    tcp flags & (fin|ack) == fin counter drop\n"
         "    tcp flags & (psh|ack) == psh counter drop\n"
         "    tcp flags & (urg|ack) == urg counter drop\n"
         "    tcp flags & (fin|urg) == (fin|urg) counter drop\n"
         "    tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|syn|rst|psh|ack|urg) counter drop\n"
         "    tcp flags & (fin|psh|urg) == (fin|psh|urg) counter drop\n"
         "    tcp flags & (syn|ack) == (syn|ack) ct state new counter drop\n"
         // `ip length > 120` here only targets oversized bare SYNs; keep for
         // classic SYN floods (TFO payload SYNs are rare on game/web ports).
         "    tcp flags & syn == syn ip length > 120 ct state new counter drop\n"
         "    ip frag-off & 0x1fff != 0 counter drop\n"
         "    ip length < 28 counter drop\n"
         "\n"
         "    ct state new tcp flags & (fin|syn|rst|ack) != syn counter drop\n"
         "\n"
         // ICMP: keep essential control (PMTUD / unreachable) even when echo
         // limiting is active, otherwise path MTU discovery breaks.
         "    ip protocol icmp icmp type { timestamp-request, timestamp-reply, address-mask-request, address-mask-reply, info-request, info-reply } counter drop\n"
         "    ip protocol icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } accept\n"
         "    ip protocol icmp icmp type echo-request meter icmp_flood { ip saddr limit rate over 10/second burst 20 packets } counter drop\n"
         "    ip protocol icmp icmp type echo-request accept\n"
         "    ip protocol icmp counter drop\n"
         "\n"
         // SSH brute force: only the meter-overflow branch is banned+dropped;
         // normal new SSH connections fall through to accept.
         "    tcp dport 22 ct state new meter ssh_brute { ip saddr limit rate over 30/minute burst 50 packets } update @banned { ip saddr timeout 1h } counter drop\n"
         "    tcp dport 22 accept\n";

    // Protected game UDP ports
    std::string game_udp_ports;
    for (const auto& p : cfg.ports) {
        if (!p.enabled || p.port == 0) continue;
        if (p.type == kPortSystem) continue;
        if (p.type == kPortGame || p.port >= 27000) {
            if (p.proto == kProtoUdp || p.proto == kProtoBoth) {
                if (!game_udp_ports.empty()) game_udp_ports += ", ";
                game_udp_ports += std::to_string(p.port);
            }
        }
    }
    if (game_udp_ports.empty()) game_udp_ports = "27015, 27016";

    s << "\n"
         "    udp dport { " << game_udp_ports << " } @th,64,32 0xffffffff meter a2s_flood { ip saddr limit rate over 15/second burst 30 packets } counter drop\n"
         "    udp dport { " << game_udp_ports << " } @th,32,16 <= 8 counter drop\n"
         "    udp dport { " << game_udp_ports << " } ip length > 1400 counter drop\n"
         "\n"
         "    tcp flags & (fin|syn|rst|ack) == syn meter syn_flood { ip saddr limit rate over 120/second burst 240 packets } counter drop\n";

    const uint32_t pps = cfg.per_ip_pps > 0 ? cfg.per_ip_pps : 1000;
    const uint32_t burst = cfg.rate_burst > 0 ? cfg.rate_burst : pps * 2;

    for (const auto& p : cfg.ports) {
        if (!p.enabled || p.port == 0) continue;
        if (p.type == kPortSystem) continue;

        uint32_t limit = pps;
        if (p.rate_limit > 0 && p.rate_limit != 100) {
            limit = (uint32_t)((uint64_t)pps * p.rate_limit / 100);
        }
        if (limit < 10) limit = 10;
        const uint32_t b = burst > limit * 2 ? burst : limit * 2;

        const std::string meter = "m_" + std::to_string(p.port) + "_" +
                                  port_proto_name(p.proto);

        if (p.proto == kProtoUdp || p.proto == kProtoBoth) {
            s << "    udp dport " << p.port << " counter comment \"port_" << p.port << "\"\n";
            s << "    udp dport " << p.port
              << " meter " << meter << "_udp"
              << " { ip saddr limit rate over " << limit << "/second burst " << b << " packets }"
              << " counter drop\n";
        }
        if (p.proto == kProtoTcp || p.proto == kProtoBoth) {
            s << "    tcp dport " << p.port << " counter comment \"port_" << p.port << "\"\n";
            s << "    tcp dport " << p.port
              << " meter " << meter << "_tcp"
              << " { ip saddr limit rate over " << limit << "/second burst " << b << " packets }"
              << " counter drop\n";
        }

        if (p.speed_mbps > 0 && p.speed_mbps < 10000) {
            uint32_t kb_sec = (uint32_t)((uint64_t)p.speed_mbps * 125);
            if (kb_sec < 64) kb_sec = 64;
            uint32_t burst_kb = kb_sec * 2;
            if (burst_kb < 128) burst_kb = 128;

            if (p.proto == kProtoUdp || p.proto == kProtoBoth) {
                s << "    udp dport " << p.port
                  << " meter " << meter << "_bw_udp"
                  << " { ip saddr limit rate over " << kb_sec << " kbytes/second burst " << burst_kb << " kbytes }"
                  << " counter drop comment \"port_bw_" << p.port << "\"\n";
            }
            if (p.proto == kProtoTcp || p.proto == kProtoBoth) {
                s << "    tcp dport " << p.port
                  << " meter " << meter << "_bw_tcp"
                  << " { ip saddr limit rate over " << kb_sec << " kbytes/second burst " << burst_kb << " kbytes }"
                  << " counter drop comment \"port_bw_" << p.port << "\"\n";
            }
        }

        if (cfg.dpi_enabled) {
            if (p.proto == kProtoUdp || p.proto == kProtoBoth) {
                s << "    udp dport " << p.port
                  << " queue num " << cfg.dpi_queue << " bypass\n";
            }
            if (p.proto == kProtoTcp || p.proto == kProtoBoth) {
                s << "    tcp dport " << p.port
                  << " queue num " << cfg.dpi_queue << " bypass\n";
            }
        }

        if (p.proto == kProtoUdp || p.proto == kProtoBoth) {
            s << "    udp dport " << p.port << " accept comment \"port_" << p.port << "_pass\"\n";
        }
        if (p.proto == kProtoTcp || p.proto == kProtoBoth) {
            s << "    tcp dport " << p.port << " accept comment \"port_" << p.port << "_pass\"\n";
        }
    }

    s << "\n"
         // Established/related traffic is accepted only after every per-flow
         // meter and the nfqueue DPI hook have had a chance to see it.
         "    ip saddr @geo_ratelimit meter m_geo_rl { ip saddr limit rate over 150/second burst 300 packets } counter drop\n"
         "    ct state established,related counter accept comment \"traffic_passed\"\n"
         "\n"
         "    ct state new meter portscan_sweep { ip saddr limit rate over 8/second burst 12 packets } update @banned { ip saddr timeout 1h } counter drop\n"
         "\n"
         "    counter drop comment \"stealth_blackhole_drop\"\n"
         "  }\n"
         "\n"
         "  chain output {\n"
         "    type filter hook output priority 0; policy accept;\n"
         "    ip daddr @geo_ratelimit meta mark set 0x42\n"
         "  }\n"
         "}\n";

    return s.str();
}

// Install base firewall ruleset
bool Nft::EnsureBase(const Config& cfg, std::string* err) {
    if (!cfg.enabled) {
        FlushAll();
        return true;
    }

    const std::string script = BuildScript(cfg);
    std::string out, e;
    if (!RunScript(script, &out, &e)) {
        if (err) *err = "nft apply failed: " + e;
        Logf(0, "EnsureBase failed: %s", e.c_str());
        return false;
    }

    Logf(2, "nftables: table %s %s installed (%zu ports)", kFamily, kTable,
         cfg.ports.size());
    return true;
}

// Remove entire table ruleset.
// `delete table` (not `destroy table`): destroy requires nft >= 1.0.8 and a new
// enough kernel, which Debian 11/12 do not ship. A missing table is not an error.
bool Nft::FlushAll() {
    std::string out, e;
    if (Run({"delete", "table", kFamily, kTable}, &out, &e)) return true;
    if (e.find("No such file") != std::string::npos ||
        e.find("does not exist") != std::string::npos) {
        return true;
    }
    Logf(1, "nftables flush failed: %s", e.c_str());
    return false;
}

// Add single banned address
bool Nft::AddBan(uint32_t ip_nbo, uint32_t ttl_secs, std::string* err) {
    const std::string ip = FormatIp(ip_nbo);
    if (ip == "0.0.0.0") return false;

    std::vector<std::string> args{
        "add", "element", kFamily, kTable, "banned", "{", ip,
    };
    if (ttl_secs > 0) {
        args.push_back("timeout");
        args.push_back(std::to_string(ttl_secs) + "s");
    }
    args.push_back("}");

    std::string out, e;
    if (!Run(args, &out, &e)) {
        if (e.find("File exists") != std::string::npos) return true;
        if (err) *err = e;
        return false;
    }
    return true;
}

// Delete single banned address
bool Nft::DelBan(uint32_t ip_nbo, std::string* err) {
    const std::string ip = FormatIp(ip_nbo);
    std::string out, e;
    if (!Run({"delete", "element", kFamily, kTable, "banned", "{", ip, "}"}, &out, &e)) {
        if (e.find("No such file") != std::string::npos ||
            e.find("does not exist") != std::string::npos) {
            return true;
        }
        if (err) *err = e;
        return false;
    }
    return true;
}

// Synchronize complete set of active bans.
// Elements are added in bounded chunks with an explicit timeout so a large
// ban table does not overflow the single-device netlink command size, and so
// the kernel-side ban window mirrors the userspace expiry instead of an
// arbitrary default. Per-element `timeout` is emitted alongside the address.
bool Nft::SyncBanSet(const std::set<uint32_t>& ips, std::string* err) {
    std::string out, e;
    if (!Run({"flush", "set", kFamily, kTable, "banned"}, &out, &e)) {
        if (err) *err = e;
        Logf(1, "SyncBanSet flush failed: %s", e.c_str());
        return false;
    }

    const size_t kChunk = 2047;
    std::ostringstream s;
    size_t in_chunk = 0;
    bool open = false;
    for (uint32_t ip : ips) {
        const std::string text = FormatIp(ip);
        if (text == "0.0.0.0") continue;
        if (!open) {
            s << "add element " << kFamily << " " << kTable << " banned { ";
            open = true;
            in_chunk = 0;
        } else {
            s << ", ";
        }
        s << text << " timeout 1h";
        if (++in_chunk >= kChunk) {
            s << " }\n";
            open = false;
        }
    }
    if (open) s << " }\n";

    if (!ips.empty() || !s.str().empty()) {
        if (!RunScript(s.str(), &out, &e)) {
            if (err) *err = e;
            Logf(1, "SyncBanSet failed: %s", e.c_str());
            return false;
        }
    }
    return true;
}

// Synchronize the trusted-source set. Ranges are CIDR/address strings.
bool Nft::SyncWhitelist(const std::vector<std::string>& entries, std::string* err) {
    std::string out, e;
    if (!Run({"flush", "set", kFamily, kTable, "whitelist"}, &out, &e)) {
        // A missing set means the base ruleset is not installed yet; not fatal.
        if (e.find("No such file") == std::string::npos &&
            e.find("does not exist") == std::string::npos) {
            if (err) *err = e;
            return false;
        }
    }
    if (entries.empty()) return true;

    std::ostringstream s;
    s << "add element " << kFamily << " " << kTable << " whitelist { ";
    bool first = true;
    for (const auto& raw : entries) {
        const std::string text = FormatIpRange(raw);
        if (text.empty()) continue;
        if (!first) s << ", ";
        s << text;
        first = false;
    }
    s << " }\n";
    if (first) return true;

    if (!RunScript(s.str(), &out, &e)) {
        if (err) *err = e;
        return false;
    }
    return true;
}

namespace {

// Fill a CIDR/range set in bounded chunks. Shared by the geo/dc helpers so a
// schema or formatting change cannot drift between them.
// `fail_closed`: when true and the flush fails for reasons other than a
// missing set, the range load is aborted and reported rather than silently
// leaving a partially populated (or empty) set protecting the host.
bool fill_range_set(const std::string& set_name,
                    const std::vector<std::pair<uint32_t, uint32_t>>& ranges,
                    std::string* err) {
    std::string out, e;
    if (!Nft::Run({"flush", "set", Nft::kFamily, Nft::kTable, set_name}, &out, &e)) {
        if (e.find("No such file") == std::string::npos &&
            e.find("does not exist") == std::string::npos) {
            if (err) *err = "flush set " + set_name + ": " + e;
            Logf(1, "%s", err ? err->c_str() : "flush failed");
            return false;
        }
    }

    const size_t kChunk = 2047;
    std::ostringstream s;
    size_t chunk = 0;
    bool open = false;
    for (const auto& r : ranges) {
        if (!open) {
            s << "add element " << Nft::kFamily << " " << Nft::kTable << " "
              << set_name << " { ";
            open = true;
            chunk = 0;
        } else {
            s << ", ";
            chunk++;
        }
        s << cidr_or_range(r.first, r.second);
        if (chunk >= kChunk) {
            s << " }\n";
            open = false;
        }
    }
    if (open) s << " }\n";

    if (ranges.empty()) return true;
    if (!Nft::RunScript(s.str(), &out, &e)) {
        if (err) *err = e;
        Logf(1, "fill set %s failed: %s", set_name.c_str(), e.c_str());
        return false;
    }
    return true;
}

} // namespace

// Populate geo-blocked IP ranges
bool Nft::SetGeoBlocks(const std::vector<std::pair<uint32_t, uint32_t>>& ranges,
                       std::string* err) {
    if (!fill_range_set("geo_blocked", ranges, err)) return false;
    Logf(2, "nftables: %zu geo ranges loaded", ranges.size());
    return true;
}

// Populate geo rate-limited IP ranges
bool Nft::SetGeoRateLimits(const std::vector<std::pair<uint32_t, uint32_t>>& ranges,
                           std::string* err) {
    if (!fill_range_set("geo_ratelimit", ranges, err)) return false;
    Logf(2, "nftables: %zu geo rate-limit ranges loaded", ranges.size());
    return true;
}

// Populate datacenter blocked IP ranges
bool Nft::SetDatacenterBlocks(const std::vector<std::pair<uint32_t, uint32_t>>& ranges,
                              std::string* err) {
    if (!fill_range_set("dc_blocked", ranges, err)) return false;
    Logf(2, "nftables: %zu datacenter ranges loaded", ranges.size());
    return true;
}

// Export current ruleset dump
std::string Nft::Dump(std::string* err) const {
    std::string out, e;
    if (!Run({"list", "table", kFamily, kTable}, &out, &e)) {
        if (err) *err = e;
        return {};
    }
    return out;
}

} // namespace femboifw
