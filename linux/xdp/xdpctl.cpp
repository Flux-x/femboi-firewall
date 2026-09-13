// Femboi Firewall XDP control utility
#include "xdp_maps.hpp"

#include <arpa/inet.h>
#include <sys/stat.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace femboifw;
using femboifw::run_argv;

namespace {
using femboifw::run_argv;

const char* kDefaultObject = "/usr/lib/femboi/femboi_xdp.o";

// Display CLI usage details
void usage() {
    std::cout <<
        "femboi-firewall-xdp — XDP datapath control\n"
        "\n"
        "  attach [--iface IF] [--mode drv|skb|hw] [--egress] [--obj PATH]\n"
        "  detach [--iface IF] [--egress]\n"
        "  block <ip> [seconds] [reason]\n"
        "  unblock <ip>\n"
        "  list-blocked [--limit N]\n"
        "  allow <ip> | disallow <ip> | list-allowed\n"
        "  stats [--watch] [--interval SEC]\n"
        "  config [--pps N] [--syn N] [--udp N] [--icmp N]\n"
        "         [--ban-secs N] [--window-ms N] [--auto-ban on|off]\n"
        "         [--icmp-filter on|off] [--enable|--disable] [--show]\n"
        "  port <n> <game|web|system|off>\n"
        "  ports\n"
        "  flush\n"
        "  doctor\n"
        "\n"
        "Global: --pin-dir DIR (default " << kXdpPinDir << ")\n";
}

bool is_root() { return geteuid() == 0; }

// Determine default network interface name
std::string default_iface() {
    std::ifstream rt("/proc/net/route");
    std::string line;
    std::getline(rt, line);
    while (std::getline(rt, line)) {
        std::istringstream ss(line);
        std::string iface, dest, gw;
        ss >> iface >> dest >> gw;
        if (dest == "00000000" && iface != "lo") return iface;
    }
    return "eth0";
}

// Convert port class enum to text
const char* port_class_name(uint8_t c) {
    switch (c) {
        case FW_PORT_GAME: return "game";
        case FW_PORT_WEB: return "web";
        case FW_PORT_SYSTEM: return "system";
        default: return "off";
    }
}

// Convert ban reason enum to text
const char* reason_name(uint32_t r) {
    switch (r) {
        case FW_BAN_PPS: return "pps";
        case FW_BAN_SYN: return "syn";
        case FW_BAN_UDP: return "udp";
        case FW_BAN_ICMP: return "icmp";
        case FW_BAN_MALFORMED: return "malformed";
        default: return "manual";
    }
}

// Format byte count with units
std::string fmt_bytes(uint64_t b) {
    char buf[64];
    if (b >= 1024ull * 1024 * 1024) snprintf(buf, sizeof(buf), "%.2f GiB", b / 1073741824.0);
    else if (b >= 1024ull * 1024) snprintf(buf, sizeof(buf), "%.2f MiB", b / 1048576.0);
    else if (b >= 1024ull) snprintf(buf, sizeof(buf), "%.2f KiB", b / 1024.0);
    else snprintf(buf, sizeof(buf), "%llu B", (unsigned long long)b);
    return buf;
}

// Attach XDP program to interface
int cmd_attach(const std::string& iface, const std::string& mode,
               const std::string& obj, bool egress, std::string* err) {
    if (obj.empty() || access(obj.c_str(), R_OK) != 0) {
        *err = "BPF object not found: " + obj;
        return 1;
    }

    std::string out;
    std::vector<std::string> load = {
        "bpftool", "prog", "load", obj, kXdpProgPin,
        "type", "xdp", "pinmaps", kXdpPinDir,
    };
    if (!run_argv(load, &out, err)) return 1;

    if (egress) {
        std::vector<std::string> load_eg = {
            "bpftool", "prog", "load", obj, kXdpProgPinEgress,
            "type", "xdp", "pinmaps", kXdpPinDir,
        };
        std::string ignored;
        run_argv(load_eg, &ignored, nullptr);
    }

    const std::string attach_mode =
        mode == "skb" ? "xdpgeneric" : (mode == "hw" ? "xdpoffload" : "xdpdrv");

    std::vector<std::string> link = {
        "ip", "link", "set", "dev", iface, attach_mode, "pinned", kXdpProgPin,
    };
    if (!run_argv(link, &out, err)) {
        if (attach_mode == "xdpdrv") {
            std::string ignored;
            std::vector<std::string> generic = {
                "ip", "link", "set", "dev", iface, "xdpgeneric", "pinned", kXdpProgPin,
            };
            if (run_argv(generic, &ignored, nullptr)) {
                std::cout << "[!] attached in generic SKB mode on " << iface << "\n";
                return 0;
            }
        }
        return 1;
    }

    std::cout << "[+] attached on " << iface << " (" << attach_mode << ")\n";
    return 0;
}

// Detach XDP program from interface
int cmd_detach(const std::string& iface, bool egress) {
    std::string out, err;
    std::vector<std::string> link = {"ip", "link", "set", "dev", iface, "xdp", "off"};
    if (!run_argv(link, &out, &err)) {
        std::cerr << "error: " << err << "\n";
        return 1;
    }
    unlink(kXdpProgPin);
    if (egress) unlink(kXdpProgPinEgress);
    std::cout << "[+] detached from " << iface << "\n";
    return 0;
}

// Display packet filter statistics
void print_stats(const struct fw_stats& s, double seconds, bool with_rates) {
    const uint64_t dropped = s.drop_blacklist + s.drop_pps + s.drop_syn +
                             s.drop_udp + s.drop_icmp + s.drop_malformed;
    const uint64_t total = s.pass + dropped;

    std::cout << "packets   : " << total << "  (pass " << s.pass
              << ", drop " << dropped << ")\n";
    std::cout << "bytes     : " << fmt_bytes(s.bytes) << "\n";
    if (with_rates && seconds > 0) {
        printf("throughput: %.0f pps  %.2f Mbps\n", (double)total / seconds,
               (double)s.bytes * 8.0 / seconds / 1e6);
    }
    std::cout << "drops     : blacklist=" << s.drop_blacklist
              << " pps=" << s.drop_pps
              << " syn=" << s.drop_syn
              << " udp=" << s.drop_udp
              << " icmp=" << s.drop_icmp
              << " malformed=" << s.drop_malformed << "\n";
    std::cout << "auto-bans : " << s.auto_bans << "\n";
}

// Read configuration from map
bool load_cfg(const XdpMaps& m, struct fw_config* c, std::string* err) {
    if (m.cfg < 0) {
        *err = "fw_cfg map not found";
        return false;
    }
    if (!m.GetConfig(c)) {
        *err = "cannot read fw_cfg";
        return false;
    }
    return true;
}

// Initialize default configuration in map
void seed_defaults(const XdpMaps& m) {
    struct fw_config c;
    memset(&c, 0, sizeof(c));
    c.enabled = 1;
    c.pps_limit = 1200;
    c.syn_limit = 120;
    c.udp_limit = 1500;
    c.icmp_limit = 40;
    c.window_ns = 1000000000ull;
    c.ban_time_ns = 600ull * 1000000000ull;
    c.flags = FW_FLAG_ICMP_ENABLED | FW_FLAG_AUTO_BAN;

    struct fw_config existing;
    if (m.GetConfig(&existing) && existing.enabled == 1) return;
    m.SetConfig(c);
}

} // namespace

// Program entrypoint for XDP control
int main(int argc, char** argv) {
    std::string command;
    std::vector<std::string> rest;
    std::string pin_dir = kXdpPinDir;
    std::string iface, mode = "drv", obj = kDefaultObject;
    bool egress = false, watch = false;
    double interval = 1.0;
    size_t limit = 500;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto need = [&](const char* what) -> std::string {
            if (i + 1 >= argc) {
                std::cerr << "error: " << what << " needs a value\n";
                exit(2);
            }
            return argv[++i];
        };

        if (a == "-h" || a == "--help") { usage(); return 0; }
        else if (a == "--pin-dir") pin_dir = need("--pin-dir");
        else if (a == "--iface" || a == "-i") iface = need("--iface");
        else if (a == "--mode") mode = need("--mode");
        else if (a == "--obj") obj = need("--obj");
        else if (a == "--egress") egress = true;
        else if (a == "--watch" || a == "-w") watch = true;
        else if (a == "--interval") interval = atof(need("--interval").c_str());
        else if (a == "--limit") limit = (size_t)strtoul(need("--limit").c_str(), nullptr, 10);
        else if (command.empty()) command = a;
        else rest.push_back(a);
    }

    if (command.empty()) { usage(); return 2; }
    if (iface.empty()) iface = default_iface();

    if (command == "doctor") {
        int bad = 0;
        std::cout << "femboi-firewall-xdp doctor\n--------------------------\n";

        if (is_root()) std::cout << "[ok]   root\n";
        else { std::cout << "[FAIL] not root\n"; bad++; }

        struct stat st{};
        if (stat("/sys/fs/bpf", &st) == 0)
            std::cout << "[ok]   bpffs mounted\n";
        else { std::cout << "[FAIL] /sys/fs/bpf missing\n"; bad++; }

        std::string out, err;
        if (run_argv({"bpftool", "version"}, &out, &err))
            std::cout << "[ok]   " << out.substr(0, out.find('\n')) << "\n";
        else { std::cout << "[FAIL] bpftool not found\n"; bad++; }

        if (run_argv({"ip", "-V"}, &out, &err))
            std::cout << "[ok]   " << out.substr(0, out.find('\n')) << "\n";
        else { std::cout << "[FAIL] iproute2 not found\n"; bad++; }

        std::cout << "[info] default interface: " << iface << "\n";
        std::cout << "[info] pin dir:           " << pin_dir << "\n";

        std::cout << "--------------------------\n";
        std::cout << (bad ? std::to_string(bad) + " problem(s) found\n"
                          : "Ready to attach.\n");
        return bad ? 1 : 0;
    }

    if (command == "attach") {
        if (!is_root()) { std::cerr << "error: attach needs root\n"; return 1; }
        mkdir("/sys/fs/bpf", 0755);
        mkdir(pin_dir.c_str(), 0700);
        std::string err;
        const int rc = cmd_attach(iface, mode, obj, egress, &err);
        if (rc != 0) { std::cerr << "error: " << err << "\n"; return rc; }

        XdpMaps maps;
        if (maps.Open(pin_dir, &err)) {
            seed_defaults(maps);
        } else {
            std::cerr << "warning: maps not open (" << err << ")\n";
        }
        return rc;
    }
    if (command == "detach") {
        if (!is_root()) { std::cerr << "error: detach needs root\n"; return 1; }
        return cmd_detach(iface, egress);
    }

    XdpMaps maps;
    std::string err;
    if (!maps.Open(pin_dir, &err)) {
        std::cerr << "error: " << err << "\n";
        return 1;
    }

    if (command == "block") {
        if (rest.empty()) { std::cerr << "usage: femboi-firewall-xdp block <ip> [secs]\n"; return 2; }
        uint32_t ip = 0;
        if (!ParseIp(rest[0], &ip)) { std::cerr << "error: bad IPv4 address\n"; return 2; }
        const uint64_t ttl = rest.size() > 1 ? strtoull(rest[1].c_str(), nullptr, 10) : 0;
        if (!maps.BlockIp(ip, ttl, FW_BAN_MANUAL, &err)) {
            std::cerr << "error: " << err << "\n";
            return 1;
        }
        std::cout << "[+] " << rest[0] << " blacklisted"
                  << (ttl ? " for " + std::to_string(ttl) + "s" : " permanently") << "\n";
        return 0;
    }

    if (command == "unblock") {
        if (rest.empty()) { std::cerr << "usage: femboi-firewall-xdp unblock <ip>\n"; return 2; }
        uint32_t ip = 0;
        if (!ParseIp(rest[0], &ip)) { std::cerr << "error: bad IPv4 address\n"; return 2; }
        if (!maps.UnblockIp(ip, &err)) { std::cerr << "error: " << err << "\n"; return 1; }
        std::cout << "[+] " << rest[0] << " unblocked\n";
        return 0;
    }

    if (command == "list-blocked") {
        const auto rows = maps.ListBlocked(limit);
        if (rows.empty()) { std::cout << "(blacklist empty)\n"; return 0; }

        const uint64_t now = bpf_sys::monotonic_ns();
        std::cout << "ip                remaining    reason      hits\n";
        std::cout << "------------------------------------------------------\n";
        for (const auto& r : rows) {
            std::string rem = "permanent";
            if (r.expires_ns) {
                const int64_t left = (int64_t)(r.expires_ns - now);
                rem = left > 0 ? std::to_string(left / 1000000000) + "s" : "expiring";
            }
            char row[160];
            snprintf(row, sizeof(row), "%-17s %-12s %-11s %u",
                     FormatIp(r.ip_nbo).c_str(), rem.c_str(),
                     reason_name(r.reason), r.hits);
            std::cout << row << "\n";
        }
        std::cout << "------------------------------------------------------\n"
                  << rows.size() << " entries\n";
        return 0;
    }

    if (command == "allow" || command == "disallow") {
        if (rest.empty()) { std::cerr << "error: " << command << " needs an IP\n"; return 2; }
        uint32_t ip = 0;
        if (!ParseIp(rest[0], &ip)) { std::cerr << "error: bad IPv4 address\n"; return 2; }
        const bool ok = (command == "allow") ? maps.AllowIp(ip) : maps.DisallowIp(ip);
        if (!ok) { std::cerr << "error: map update failed\n"; return 1; }
        std::cout << "[+] " << rest[0]
                  << (command == "allow" ? " whitelisted" : " removed from whitelist") << "\n";
        return 0;
    }

    if (command == "list-allowed") {
        const auto rows = maps.ListAllowed(limit);
        if (rows.empty()) { std::cout << "(whitelist empty)\n"; return 0; }
        for (uint32_t ip : rows) std::cout << FormatIp(ip) << "\n";
        return 0;
    }

    if (command == "flush") {
        if (!maps.FlushBlacklist()) { std::cerr << "error: flush failed\n"; return 1; }
        std::cout << "[+] blacklist flushed\n";
        return 0;
    }

    if (command == "stats") {
        if (!watch) {
            struct fw_stats s;
            if (!maps.ReadStats(&s)) { std::cerr << "error: cannot read stats\n"; return 1; }
            print_stats(s, 0, false);
            return 0;
        }
        struct fw_stats prev, cur;
        if (!maps.ReadStats(&prev)) { std::cerr << "error: cannot read stats\n"; return 1; }
        for (int tick = 0; tick < 100000; ++tick) {
            std::this_thread::sleep_for(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::duration<double>(interval)));
            if (!maps.ReadStats(&cur)) break;

            struct fw_stats d;
            memset(&d, 0, sizeof(d));
            d.pass = cur.pass - prev.pass;
            d.bytes = cur.bytes - prev.bytes;
            d.drop_blacklist = cur.drop_blacklist - prev.drop_blacklist;
            d.drop_pps = cur.drop_pps - prev.drop_pps;
            d.drop_syn = cur.drop_syn - prev.drop_syn;
            d.drop_udp = cur.drop_udp - prev.drop_udp;
            d.drop_icmp = cur.drop_icmp - prev.drop_icmp;
            d.drop_malformed = cur.drop_malformed - prev.drop_malformed;
            d.auto_bans = cur.auto_bans;

            printf("\033[H\033[J");
            std::cout << "femboi-firewall-xdp live (" << interval << "s)\n\n";
            print_stats(d, interval, true);
            std::cout << "\nblacklist size: " << maps.BlacklistCount() << "\n";
            fflush(stdout);
            prev = cur;
        }
        return 0;
    }

    if (command == "port") {
        if (rest.size() < 2) { std::cerr << "usage: femboi-firewall-xdp port <n> <game|web|system|off>\n"; return 2; }
        const long port = strtol(rest[0].c_str(), nullptr, 10);
        if (port <= 0 || port > 65535) { std::cerr << "error: port must be 1..65535\n"; return 2; }

        uint8_t cls = FW_PORT_UNPROTECTED;
        if (rest[1] == "game") cls = FW_PORT_GAME;
        else if (rest[1] == "web") cls = FW_PORT_WEB;
        else if (rest[1] == "system") cls = FW_PORT_SYSTEM;
        else if (rest[1] != "off") {
            std::cerr << "error: invalid port class\n";
            return 2;
        }
        if (!maps.SetPortClass((uint16_t)port, cls)) {
            std::cerr << "error: cannot update port_class\n";
            return 1;
        }
        std::cout << "[+] port " << port << " -> " << port_class_name(cls) << "\n";
        return 0;
    }

    if (command == "ports") {
        std::cout << "port   class\n";
        std::cout << "----------------\n";
        for (uint32_t p = 1; p <= 65535; ++p) {
            uint8_t cls = 0;
            if (maps.GetPortClass((uint16_t)p, &cls) && cls != FW_PORT_UNPROTECTED) {
                printf("%-6u %s\n", p, port_class_name(cls));
            }
        }
        return 0;
    }

    if (command == "config") {
        struct fw_config c;
        if (!load_cfg(maps, &c, &err)) { std::cerr << "error: " << err << "\n"; return 1; }

        bool changed = false;
        for (size_t i = 0; i < rest.size(); ++i) {
            const std::string& a = rest[i];
            auto val = [&](const char* what) -> std::string {
                if (i + 1 >= rest.size()) { std::cerr << "error: " << what << " needs a value\n"; exit(2); }
                return rest[++i];
            };
            if (a == "--pps") { c.pps_limit = (uint32_t)strtoul(val("--pps").c_str(), nullptr, 10); changed = true; }
            else if (a == "--syn") { c.syn_limit = (uint32_t)strtoul(val("--syn").c_str(), nullptr, 10); changed = true; }
            else if (a == "--udp") { c.udp_limit = (uint32_t)strtoul(val("--udp").c_str(), nullptr, 10); changed = true; }
            else if (a == "--icmp") { c.icmp_limit = (uint32_t)strtoul(val("--icmp").c_str(), nullptr, 10); changed = true; }
            else if (a == "--ban-secs") { c.ban_time_ns = strtoull(val("--ban-secs").c_str(), nullptr, 10) * 1000000000ull; changed = true; }
            else if (a == "--window-ms") { c.window_ns = strtoull(val("--window-ms").c_str(), nullptr, 10) * 1000000ull; changed = true; }
            else if (a == "--auto-ban") {
                const bool on = val("--auto-ban") != "off";
                if (on) c.flags |= FW_FLAG_AUTO_BAN; else c.flags &= ~FW_FLAG_AUTO_BAN;
                changed = true;
            }
            else if (a == "--icmp-filter") {
                const bool on = val("--icmp-filter") != "off";
                if (on) c.flags |= FW_FLAG_ICMP_ENABLED; else c.flags &= ~FW_FLAG_ICMP_ENABLED;
                changed = true;
            }
            else if (a == "--enable") { c.enabled = 1; changed = true; }
            else if (a == "--disable") { c.enabled = 0; changed = true; }
            else if (a == "--show") { }
            else { std::cerr << "error: unknown config flag " << a << "\n"; return 2; }
        }

        if (changed && !maps.SetConfig(c)) {
            std::cerr << "error: cannot write fw_cfg\n";
            return 1;
        }

        if (changed) std::cout << "[+] configuration updated\n";
        std::cout << "enabled      : " << (c.enabled ? "yes" : "no") << "\n"
                  << "pps_limit    : " << c.pps_limit << " pps/source\n"
                  << "syn_limit    : " << c.syn_limit << " SYN/source\n"
                  << "udp_limit    : " << c.udp_limit << " UDP pkt/source\n"
                  << "icmp_limit   : " << c.icmp_limit << " ICMP/source\n"
                  << "window       : " << (c.window_ns / 1000000ull) << " ms\n"
                  << "ban_time     : " << (c.ban_time_ns / 1000000000ull) << " s\n"
                  << "auto_ban     : " << ((c.flags & FW_FLAG_AUTO_BAN) ? "yes" : "no") << "\n"
                  << "icmp_filter  : " << ((c.flags & FW_FLAG_ICMP_ENABLED) ? "allow+limit" : "drop all") << "\n";
        return 0;
    }

    std::cerr << "unknown command: " << command << "\n\n";
    usage();
    return 2;
}
