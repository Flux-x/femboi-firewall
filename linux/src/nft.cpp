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

// Install base firewall ruleset
bool Nft::EnsureBase(const Config& cfg, std::string* err) {
    if (!cfg.enabled) {
        FlushAll();
        return true;
    }

    std::ostringstream s;

    // Flush prior table state
    s << "add table " << kFamily << " " << kTable << "\n";
    s << "delete table " << kFamily << " " << kTable << "\n";

    s << "table " << kFamily << " " << kTable << " {\n";

    // Dynamic drop sets
    s << "  set banned {\n"
         "    type ipv4_addr\n"
         "    flags dynamic, timeout\n"
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

    // Prerouting raw hook
    s << "  chain prerouting {\n"
         "    type filter hook prerouting priority -310; policy accept;\n"
         "    ip saddr @banned counter drop\n"
         "    ip saddr . th dport @banned_ports counter drop\n"
         "    ip saddr @geo_blocked counter drop\n"
         "    ip saddr @dc_blocked counter drop\n"
         "  }\n";

    // Input packet filter chain
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
         "    ip saddr @banned counter drop\n"
         "    ip saddr . th dport @banned_ports counter drop\n"
         "    ip saddr @geo_blocked counter drop\n"
         "    ip saddr @dc_blocked counter drop\n"
         "    ip saddr @geo_ratelimit meter m_geo_rl { ip saddr limit rate over 150/second burst 300 packets } counter drop\n"
         "\n"
         "    ct state established,related counter accept comment \"traffic_passed\"\n"
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
         "    tcp dport { 21, 23, 25, 110, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200 } update @banned { ip saddr timeout 1h } counter drop\n"
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
         "    tcp flags & syn == syn ip length > 120 counter drop\n"
         "    ip frag-off & 0x1fff != 0 counter drop\n"
         "    ip length < 28 counter drop\n"
         "\n"
         "    ct state new tcp flags & (fin|syn|rst|ack) != syn counter drop\n"
         "\n"
         "    meter subnet24_flood { ip saddr and 255.255.255.0 limit rate over 4000/second burst 8000 packets } counter drop\n"
         "\n"
         "    ip protocol icmp icmp type { timestamp-request, timestamp-reply, address-mask-request, address-mask-reply, info-request, info-reply } counter drop\n"
         "    ip protocol icmp icmp type echo-request meter icmp_flood { ip saddr limit rate over 2/second burst 4 packets } counter drop\n"
         "    ip protocol icmp icmp type echo-request accept\n"
         "    ip protocol icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } accept\n"
         "    ip protocol icmp counter drop\n"
         "\n"
         "    tcp dport 22 ct state new meter ssh_brute { ip saddr limit rate over 30/minute burst 50 packets } accept\n"
         "    tcp dport 22 ct state new update @banned { ip saddr timeout 1h } counter drop\n"
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

    std::string out, e;
    if (!RunScript(s.str(), &out, &e)) {
        if (err) *err = "nft apply failed: " + e;
        Logf(0, "EnsureBase failed: %s", e.c_str());
        return false;
    }

    Logf(2, "nftables: table %s %s installed (%zu ports)", kFamily, kTable,
         cfg.ports.size());
    return true;
}

// Remove entire table ruleset
bool Nft::FlushAll() {
    std::string out, e;
    if (Run({"destroy", "table", kFamily, kTable}, &out, &e)) return true;
    if (e.find("No such file") != std::string::npos) return true;
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

// Synchronize complete set of active bans
bool Nft::SyncBanSet(const std::set<uint32_t>& ips, std::string* err) {
    std::ostringstream s;
    s << "flush set " << kFamily << " " << kTable << " banned\n";
    if (!ips.empty()) {
        s << "add element " << kFamily << " " << kTable << " banned { ";
        bool first = true;
        for (uint32_t ip : ips) {
            const std::string text = FormatIp(ip);
            if (text == "0.0.0.0") continue;
            if (!first) s << ", ";
            s << text;
            first = false;
        }
        s << " }\n";
    }

    std::string out, e;
    if (!RunScript(s.str(), &out, &e)) {
        if (err) *err = e;
        Logf(1, "SyncBanSet failed: %s", e.c_str());
        return false;
    }
    return true;
}

// Populate geo-blocked IP ranges
bool Nft::SetGeoBlocks(const std::vector<std::pair<uint32_t, uint32_t>>& ranges,
                       std::string* err) {
    std::ostringstream s;
    s << "flush set " << kFamily << " " << kTable << " geo_blocked\n";

    size_t chunk = 0;
    bool open = false;
    for (const auto& r : ranges) {
        if (!open) {
            s << "add element " << kFamily << " " << kTable << " geo_blocked { ";
            open = true;
            chunk = 0;
        } else {
            s << ", ";
            chunk++;
        }
        s << cidr_or_range(r.first, r.second);
        if (chunk >= 2047) {
            s << " }\n";
            open = false;
        }
    }
    if (open) s << " }\n";

    std::string out, e;
    if (!RunScript(s.str(), &out, &e)) {
        if (err) *err = e;
        Logf(1, "SetGeoBlocks failed: %s", e.c_str());
        return false;
    }
    Logf(2, "nftables: %zu geo ranges loaded", ranges.size());
    return true;
}

// Populate geo rate-limited IP ranges
bool Nft::SetGeoRateLimits(const std::vector<std::pair<uint32_t, uint32_t>>& ranges,
                           std::string* err) {
    std::ostringstream s;
    s << "flush set " << kFamily << " " << kTable << " geo_ratelimit\n";

    size_t chunk = 0;
    bool open = false;
    for (const auto& r : ranges) {
        if (!open) {
            s << "add element " << kFamily << " " << kTable << " geo_ratelimit { ";
            open = true;
            chunk = 0;
        } else {
            s << ", ";
            chunk++;
        }
        s << cidr_or_range(r.first, r.second);
        if (chunk >= 2047) {
            s << " }\n";
            open = false;
        }
    }
    if (open) s << " }\n";

    std::string out, e;
    if (!RunScript(s.str(), &out, &e)) {
        if (err) *err = e;
        Logf(1, "SetGeoRateLimits failed: %s", e.c_str());
        return false;
    }
    Logf(2, "nftables: %zu geo rate-limit ranges loaded", ranges.size());
    return true;
}

// Populate datacenter blocked IP ranges
bool Nft::SetDatacenterBlocks(const std::vector<std::pair<uint32_t, uint32_t>>& ranges,
                              std::string* err) {
    std::ostringstream s;
    s << "flush set " << kFamily << " " << kTable << " dc_blocked\n";

    size_t chunk = 0;
    bool open = false;
    for (const auto& r : ranges) {
        if (!open) {
            s << "add element " << kFamily << " " << kTable << " dc_blocked { ";
            open = true;
            chunk = 0;
        } else {
            s << ", ";
            chunk++;
        }
        s << cidr_or_range(r.first, r.second);
        if (chunk >= 2047) {
            s << " }\n";
            open = false;
        }
    }
    if (open) s << " }\n";

    std::string out, e;
    if (!RunScript(s.str(), &out, &e)) {
        if (err) *err = e;
        Logf(1, "SetDatacenterBlocks failed: %s", e.c_str());
        return false;
    }
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
