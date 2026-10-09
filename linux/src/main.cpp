// Femboi Firewall daemon and CLI
#include "fw.hpp"
#include "fw_portable.hpp"
#include "proc.hpp"
#include "../xdp/xdp_maps.hpp"

#include <sys/types.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <thread>

namespace femboifw {
namespace {

constexpr const char* kDefaultConfig = "/etc/femboi/firewall.conf";
constexpr const char* kDefaultLog = "/var/log/femboi-firewall.log";

std::atomic<bool> g_stop{false};
std::atomic<bool> g_reload{false};

// Handle process control signals
void on_signal(int sig) {
    if (sig == SIGHUP) {
        g_reload.store(true, std::memory_order_relaxed);
    } else {
        g_stop.store(true, std::memory_order_relaxed);
    }
}

// Register signal handlers
void InstallSignals() {
    struct sigaction sa{};
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGHUP, &sa, nullptr);
    signal(SIGPIPE, SIG_IGN);
}

// Load geo-blocking rules file
void LoadGeoRules(const std::string& path, std::map<std::string, CountryRule>& out) {
    std::ifstream in(path);
    if (!in) {
        Logf(2, "geo rules: %s not present", path.c_str());
        return;
    }

    std::string line;
    CountryRule cur;
    bool have = false;

    auto flush = [&]() {
        if (have && cur.code.size() == 2) out[cur.code] = cur;
        cur = CountryRule{};
        have = false;
    };

    while (std::getline(in, line)) {
        size_t b = line.find_first_not_of(" \t\r\n");
        if (b == std::string::npos) continue;
        std::string t = line.substr(b);
        if (t[0] == '{') { flush(); have = true; continue; }
        if (t[0] == '}') { flush(); continue; }
        if (!have) continue;

        size_t colon = t.find(':');
        if (colon == std::string::npos) continue;
        std::string k = t.substr(0, colon);
        std::string v = t.substr(colon + 1);
        auto strip = [](std::string& s) {
            size_t p1 = s.find_first_not_of(" \t\r\n\",");
            size_t p2 = s.find_last_not_of(" \t\r\n\",");
            s = (p1 == std::string::npos) ? "" : s.substr(p1, p2 - p1 + 1);
        };
        strip(k); strip(v);

        if (k == "code") cur.code = v;
        else if (k == "name") cur.name = v;
        else if (k == "action") cur.action = atoi(v.c_str());
        else if (k == "max_pps") cur.max_pps = (uint32_t)strtoul(v.c_str(), nullptr, 10);
        else if (k == "max_conns") cur.max_connections = (uint32_t)strtoul(v.c_str(), nullptr, 10);
        else if (k == "block_udp") cur.block_udp = (v == "true" || v == "1");
    }
    flush();
}

// Build list of rate-limited ranges
std::vector<std::pair<uint32_t, uint32_t>>
BuildGeoRateRanges(const GeoDb& db, const std::map<std::string, CountryRule>& rules) {
    std::vector<std::pair<uint32_t, uint32_t>> out;
    if (rules.empty() || !db.loaded()) return out;

    for (const auto& r : db.ranges()) {
        auto it = rules.find(std::string(r.cc, 2));
        if (it == rules.end()) continue;
        if (it->second.action == kGeoRateLimit || it->second.action == kGeoUnderAttack) {
            out.emplace_back(r.start_ip, r.end_ip);
        }
    }

    std::sort(out.begin(), out.end());
    std::vector<std::pair<uint32_t, uint32_t>> merged;
    for (const auto& r : out) {
        if (!merged.empty() && r.first <= merged.back().second) {
            if (r.second > merged.back().second) merged.back().second = r.second;
            continue;
        }
        merged.push_back(r);
    }
    return merged;
}

// Build list of blocked country ranges
std::vector<std::pair<uint32_t, uint32_t>>
BuildGeoBlockRanges(const GeoDb& db, const std::map<std::string, CountryRule>& rules) {
    std::vector<std::pair<uint32_t, uint32_t>> out;
    if (rules.empty() || !db.loaded()) return out;

    for (const auto& r : db.ranges()) {
        auto it = rules.find(std::string(r.cc, 2));
        if (it == rules.end()) continue;
        if (it->second.action != kGeoBlock) continue;
        out.emplace_back(r.start_ip, r.end_ip);
    }

    std::sort(out.begin(), out.end());
    std::vector<std::pair<uint32_t, uint32_t>> merged;
    for (const auto& r : out) {
        if (!merged.empty() && r.first <= merged.back().second) {
            if (r.second > merged.back().second) merged.back().second = r.second;
            continue;
        }
        merged.push_back(r);
    }
    return merged;
}

// Print command-line usage information
void Usage() {
    std::cout <<
        "Femboi Firewall — Linux DDoS mitigation engine\n"
        "\n"
        "Usage: femboi-firewall <command> [options]\n"
        "\n"
        "Commands:\n"
        "  daemon [-c FILE]     Run enforcement daemon\n"
        "  apply  [-c FILE]     Install nftables ruleset\n"
        "  status [-c FILE]     Print firewall status JSON\n"
        "  ports  [-c FILE]     Print configured ports\n"
        "  ruleset [-c FILE]    Print generated nftables script (dry-run with nft -c)\n"
        "  list                 List active bans\n"
        "  ban <ip> [secs]      Ban IP address\n"
        "  unban <ip>           Lift ban on IP address\n"
        "  geo <CC> <action>    Update country rule\n"
        "  set <key> <value>    Update protection setting\n"
        "  hwid                 Print machine HWID\n"
        "  doctor               Check system dependencies\n"
        "  nft-flush            Remove nftables table\n"
        "\n"
        "Options:\n"
        "  -c, --config FILE    Config path (default " << kDefaultConfig << ")\n"
        "  -v, --verbose        Verbose DEBUG logging\n"
        "  -q, --quiet          Quiet WARN logging\n"
        "  -h, --help           Show help message\n";
}

// Diagnose system configuration and prerequisites
int CmdDoctor() {
    int problems = 0;
    std::cout << "Femboi Firewall doctor\n-----------------------\n";

    if (Nft::Available()) {
        std::string out, err;
        Nft::Run({"--version"}, &out, &err);
        std::cout << "[ok]   nftables:     " << (out.empty() ? err : out.substr(0, 60));
        if (out.empty() || out.back() != '\n') {
            std::cout << "\n";
        }
    } else {
        std::cout << "[FAIL] nft not found (install nftables)\n";
        problems++;
    }

    if (geteuid() == 0) {
        std::cout << "[ok]   root:         CAP_NET_ADMIN available\n";
    } else {
        std::cout << "[FAIL] not root (requires CAP_NET_ADMIN)\n";
        problems++;
    }

    std::cout << "[ok]   machine name: " << MachineName() << "\n";
    std::cout << "[ok]   hwid:         " << MachineHwid() << "\n";

    Config cfg;
    cfg.ApplyDefaults();
    std::string err;
    if (cfg.Load(kDefaultConfig, &err)) {
        std::cout << "[ok]   config:       " << kDefaultConfig << "\n";
    } else {
        std::cout << "[warn] config:       " << err << " (using defaults)\n";
    }

    GeoDb geo;
    if (geo.Load(cfg.geoip_path, &err)) {
        std::cout << "[ok]   geoip:        " << geo.size() << " ranges\n";
    } else {
        std::cout << "[warn] geoip:        " << err << "\n";
    }

    std::cout << "-----------------------\n";
    if (problems == 0) {
        std::cout << "All dependencies verified.\n";
    } else {
        std::cout << problems << " problem(s) found.\n";
    }
    return problems == 0 ? 0 : 1;
}

// Count banned elements in the kernel set.
// Uses `nft -j` (JSON) rather than scraping the human-readable set dump: the
// text form wraps the first element onto the `elements = {` line, so a naive
// line scan undercounts by one and miscounts multi-element rows.
struct NftBanRow {
    std::string ip;
    std::string remaining;
};

// Minimal scan of `nft -j` output for set element objects. Each element is a
// `{"elem":{"val":"<ip>","expires":<secs>,...}}` entry.
std::vector<NftBanRow> ParseBanJson(const std::string& json) {
    std::vector<NftBanRow> rows;
    size_t pos = 0;
    while ((pos = json.find("\"elem\"", pos)) != std::string::npos) {
        size_t obj = json.find('{', pos);
        if (obj == std::string::npos) break;
        size_t val = json.find("\"val\"", obj);
        if (val == std::string::npos) break;
        size_t q1 = json.find('"', val + 5);
        size_t q2 = q1 == std::string::npos ? std::string::npos : json.find('"', q1 + 1);
        if (q1 == std::string::npos || q2 == std::string::npos) break;
        NftBanRow row;
        row.ip = json.substr(q1 + 1, q2 - q1 - 1);
        row.remaining = "permanent";
        const size_t exp = json.find("\"expires\"", q2);
        const size_t next = json.find("\"elem\"", q2);
        if (exp != std::string::npos && (next == std::string::npos || exp < next)) {
            size_t colon = json.find(':', exp);
            if (colon != std::string::npos) {
                size_t s = colon + 1;
                while (s < json.size() && (json[s] == ' ' || json[s] == '\t')) s++;
                size_t e = s;
                while (e < json.size() && isdigit((unsigned char)json[e])) e++;
                if (e > s) row.remaining = json.substr(s, e - s) + "s";
            }
        }
        rows.push_back(std::move(row));
        pos = q2 + 1;
    }
    return rows;
}

std::vector<NftBanRow> ListBansJson() {
    std::string out, err;
    if (!Nft::Run({"list", "set", Nft::kFamily, Nft::kTable, "banned", "-j"}, &out, &err)) {
        // Fallback for nft builds without -j support.
        if (!Nft::Run({"list", "set", Nft::kFamily, Nft::kTable, "banned"}, &out, &err)) {
            return {};
        }
    }
    return ParseBanJson(out);
}

size_t CountBannedElements() {
    return ListBansJson().size();
}

// Print status in JSON format
int CmdStatus(const Config& cfg, const BanTable& bans, bool engine_up) {
    const int64_t now = NowEpoch();
    std::string err;
    Nft nft;
    const std::string ruleset = nft.Dump(&err);
    const size_t live_bans = ruleset.empty() ? 0 : CountBannedElements();
    (void)bans;

    std::cout << "{\n";
    std::cout << "  \"engine\": \"" << (engine_up ? "running" : "stopped") << "\",\n";
    std::cout << "  \"enabled\": " << (cfg.enabled ? "true" : "false") << ",\n";
    std::cout << "  \"platform\": \"linux\",\n";
    std::cout << "  \"model\": \"nftables\",\n";
    std::cout << "  \"hwid\": \"" << MachineHwid() << "\",\n";
    std::cout << "  \"machine_name\": \"" << MachineName() << "\",\n";
    std::cout << "  \"nft_table_present\": " << (!ruleset.empty() ? "true" : "false") << ",\n";
    std::cout << "  \"active_bans\": " << live_bans << ",\n";

    std::cout << "  \"ports\": [";
    bool first = true;
    for (const auto& p : cfg.ports) {
        if (!p.enabled || p.port == 0) continue;
        if (!first) std::cout << ", ";
        first = false;
        std::cout << "{\"port\": " << p.port
                  << ", \"proto\": \"" << port_proto_name(p.proto)
                  << "\", \"type\": \"" << port_type_name(p.type)
                  << "\", \"rate_limit\": " << p.rate_limit << "}";
    }
    std::cout << "],\n";
    std::cout << "  \"time\": " << now << "\n";
    std::cout << "}\n";
    return 0;
}

// Print configured port rules
int CmdPorts(const Config& cfg) {
    std::cout << "port   proto  type    rate%  speed(Mbps)  protected\n";
    std::cout << "--------------------------------------------------------\n";
    for (const auto& p : cfg.ports) {
        if (p.port == 0) continue;
        if (!p.enabled) continue;
        const bool prot = p.type != kPortSystem;
        char line[160];
        snprintf(line, sizeof(line), "%-6u %-6s %-7s %-6u %-12u %s",
                 p.port, port_proto_name(p.proto), port_type_name(p.type),
                 p.rate_limit, p.speed_mbps, prot ? "yes" : "no (management)");
        std::cout << line << "\n";
    }
    return 0;
}

// List active IP bans (JSON-backed, see ListBansJson).
int CmdList(const Config& cfg) {
    (void)cfg;
    std::string err;
    Nft nft;
    if (nft.Dump(&err).empty()) {
        if (err.find("No such file") != std::string::npos ||
            err.find("does not exist") != std::string::npos) {
            std::cout << "Firewall table not installed.\n";
            return 1;
        }
        std::cerr << "error: " << err << "\n";
        return 1;
    }

    const auto rows = ListBansJson();
    std::cout << "ip                remaining   \n";
    std::cout << "---------------------------------\n";
    for (const auto& r : rows) {
        char line[128];
        snprintf(line, sizeof(line), "%-17s %s", r.ip.c_str(), r.remaining.c_str());
        std::cout << line << "\n";
    }
    if (rows.empty()) std::cout << "(no active bans)\n";
    else std::cout << "---------------------------------\n" << rows.size() << " active ban(s)\n";
    return 0;
}

struct EngineState {
    Config cfg;
    GeoDb geo;
    AsnFilter asn;
    BanTable bans;
    Counters counters;
    std::mutex feed_mu;
    std::vector<BlockEvent> feed;
    std::atomic<bool> running{false};

    void NoteBlock(const std::string& ip, uint16_t port, const std::string& type,
                   const std::string& reason) {
        if (ip.empty() || ip == "0.0.0.0" || ip == "-") return;
        std::lock_guard<std::mutex> lk(feed_mu);
        if (feed.size() >= 512) feed.erase(feed.begin(), feed.begin() + 128);
        BlockEvent e;
        e.ip = ip;
        e.port = port;
        e.type = type;
        e.reason = reason;
        e.at = NowEpoch();
        feed.push_back(e);
    }

    std::vector<BlockEvent> DrainFeed(size_t max_n) {
        std::lock_guard<std::mutex> lk(feed_mu);
        std::vector<BlockEvent> out;
        const size_t n = std::min(max_n, feed.size());
        out.assign(feed.begin(), feed.begin() + (long)n);
        feed.erase(feed.begin(), feed.begin() + (long)n);
        return out;
    }
};

// Translate the daemon config into the XDP `fw_config` block and mirror the
// nftables ban set into the XDP blacklist.
//
// Contract (fixes split-brain): userspace is additive only here. Entries that
// exist in XDP but not in the nft set are XDP's own auto-bans and MUST NOT be
// deleted from here, otherwise every reload wipes live datapath bans. Explicit
// removal happens in `unban`/`nft-flush`, which clear both tiers.
void SyncXdp(const Config& cfg, const std::set<uint32_t>& bans) {
    if (!cfg.xdp_enabled) return;

    static bool warned = false;
    XdpMaps xdp;
    std::string err;
    if (!xdp.Open(cfg.xdp_pin_dir, &err)) {
        if (!warned) {
            Logf(1, "XDP enabled but unavailable: %s", err.c_str());
            warned = true;
        }
        return;
    }

    // Config -> fw_cfg mapping. syn/udp/icmp limits are derived from the single
    // per-IP budget (there is no separate config surface for them yet).
    struct fw_config c;
    memset(&c, 0, sizeof(c));
    c.enabled = cfg.enabled ? 1u : 0u;
    c.pps_limit = cfg.per_ip_pps;
    c.syn_limit = cfg.per_ip_pps / 4u;
    c.udp_limit = cfg.per_ip_pps;
    c.icmp_limit = 20u;
    c.window_ns = 1000000000ull;
    c.ban_time_ns = (uint64_t)(cfg.ban_seconds ? cfg.ban_seconds : 3600) * 1000000000ull;
    c.flags = FW_FLAG_ICMP_ENABLED;
    if (cfg.auto_ban) c.flags |= FW_FLAG_AUTO_BAN;
    xdp.SetConfig(c);

    for (const auto& p : cfg.ports) {
        if (p.port == 0) continue;
        uint8_t cls = FW_PORT_UNPROTECTED;
        if (p.enabled) {
            if (p.type == kPortSystem) cls = FW_PORT_SYSTEM;
            else if (p.type == kPortWeb) cls = FW_PORT_WEB;
            else cls = FW_PORT_GAME;
        }
        xdp.SetPortClass(p.port, cls);
    }

    std::set<uint32_t> present;
    for (const auto& row : xdp.ListBlocked(200000)) present.insert(row.ip_nbo);

    size_t added = 0;
    const uint32_t ttl = cfg.ban_seconds ? cfg.ban_seconds : 3600;
    for (uint32_t ip : bans) {
        if (present.count(ip)) continue;
        if (xdp.BlockIp(ip, ttl, FW_BAN_MANUAL)) added++;
    }

    if (added) {
        Logf(3, "xdp mirror: +%zu (nft set %zu)", added, bans.size());
    }
}

// Emit the hardening sysctls to /etc/sysctl.d/90-femboi.conf instead of
// writing /proc/sys on every apply. Writing runtime values clobbered
// operator-chosen tuning (rp_filter=1 breaks WireGuard/Tailscale/Docker
// asymmetric routing) with no way to revert. The file is idempotent and is
// picked up by systemd-sysctl; operators can override or remove it.
void WriteSysctlDropIn() {
    const char* kPath = "/etc/sysctl.d/90-femboi.conf";
    const std::string body =
        "# Installed by femboi-firewall. Remove or edit to opt out.\n"
        "net.ipv4.tcp_syncookies = 1\n"
        "net.ipv4.tcp_rfc1337 = 1\n"
        "net.ipv4.tcp_max_syn_backlog = 8192\n"
        "net.core.somaxconn = 8192\n"
        "net.core.netdev_max_backlog = 16384\n"
        "net.ipv4.icmp_echo_ignore_broadcasts = 1\n"
        "net.ipv4.icmp_ignore_bogus_error_responses = 1\n"
        "net.ipv4.icmp_ratelimit = 100\n"
        "net.ipv4.icmp_ratemask = 6168\n"
        "net.ipv4.tcp_fin_timeout = 15\n"
        "net.ipv4.conf.all.accept_redirects = 0\n"
        "net.ipv4.conf.all.send_redirects = 0\n"
        // NOTE: rp_filter is intentionally NOT set here.
        ;

    std::ifstream existing(kPath);
    std::stringstream cur;
    cur << existing.rdbuf();
    if (cur.str() == body) return;

    std::ofstream out(kPath, std::ios::trunc);
    if (!out) {
        Logf(1, "cannot write %s (sysctl hardening skipped)", kPath);
        return;
    }
    out << body;
    if (!out) Logf(1, "sysctl drop-in write failed: %s", kPath);
}

// Apply the sysctl drop-in at most once per daemon run before rules install.
void EnsureSysctlDropIn() {
    static std::once_flag once;
    std::call_once(once, WriteSysctlDropIn);
}

// Apply configuration and rulesets to kernel
bool ApplyAll(EngineState& st, bool log_it) {
    EnsureSysctlDropIn();
    std::string err;
    Nft nft;

    if (!nft.EnsureBase(st.cfg, &err)) {
        Logf(0, "cannot install nftables ruleset: %s", err.c_str());
        return false;
    }

    // Trusted sources must be installed before any auto-ban rule can fire.
    if (!nft.SyncWhitelist(st.cfg.whitelist, &err)) {
        Logf(1, "cannot sync whitelist: %s", err.c_str());
    }

    // Preserve kernel-side bans (CLI `ban`, previously written elements) across
    // reloads; only add entries that userspace knows about.
    const auto active = st.bans.ActiveSet(NowEpoch());
    if (!nft.SyncBanSet(active, &err)) {
        Logf(1, "cannot sync ban set: %s", err.c_str());
    }

    if (st.cfg.datacenter_filter && st.asn.range_count() > 0) {
        nft.SetDatacenterBlocks(st.asn.ranges(), &err);
    } else {
        nft.SetDatacenterBlocks({}, &err);
    }

    if (st.cfg.geo_enabled && st.geo.loaded()) {
        std::map<std::string, CountryRule> rules;
        LoadGeoRules(st.cfg.rules_path, rules);
        const auto ranges = BuildGeoBlockRanges(st.geo, rules);
        nft.SetGeoBlocks(ranges, &err);
        const auto rate_ranges = BuildGeoRateRanges(st.geo, rules);
        nft.SetGeoRateLimits(rate_ranges, &err);
    } else {
        nft.SetGeoBlocks({}, &err);
        nft.SetGeoRateLimits({}, &err);
    }

    if (log_it) {
        Logf(2, "engine applied: %zu bans, %zu geo ranges, %zu datacenter ranges",
             active.size(), st.geo.size(), st.asn.range_count());
    }

    SyncXdp(st.cfg, active);
    return true;
}

// Periodically clean expired bans
void MaintenanceThread(EngineState& st) {
    while (!g_stop.load()) {
        for (int i = 0; i < 5 && !g_stop.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (g_stop.load()) break;

        const int64_t now = NowEpoch();
        const size_t before = st.bans.size();
        st.bans.Sweep(now);
        if (st.bans.size() != before) {
            std::string err;
            Nft nft;
            nft.SyncBanSet(st.bans.ActiveSet(now), &err);
            Logf(3, "swept expired bans (%zu -> %zu)", before, st.bans.size());
        }
    }
}

// Run main daemon loop
int CmdDaemon(Config& cfg, const std::string& config_path) {
    if (geteuid() != 0) {
        Logf(0, "daemon requires root");
        return 1;
    }
    if (!Nft::Available()) {
        Logf(0, "nft not found (install nftables)");
        return 1;
    }

    EngineState st;
    st.cfg = cfg;
    st.asn.Init();

    std::string err;
    if (!st.geo.Load(cfg.geoip_path, &err)) {
        Logf(1, "geoip unavailable (%s)", err.c_str());
    }

    InstallSignals();

    if (!cfg.enabled) {
        // Stay resident and respond to SIGHUP so `set enabled 1` (which triggers
        // a reload) actually takes effect without a manual restart.
        Logf(1, "config disabled; waiting for reload");
        while (!g_stop.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            if (g_reload.exchange(false)) {
                Config fresh = st.cfg;
                std::string e2;
                if (fresh.Load(config_path, &e2)) {
                    st.cfg = fresh;
                    if (st.cfg.enabled) {
                        Logf(2, "enabled via reload");
                        break;
                    }
                } else {
                    Logf(1, "reload failed: %s", e2.c_str());
                }
            }
        }
        if (g_stop.load()) return 0;
    }

    if (!ApplyAll(st, true)) {
        return 1;
    }
    st.running.store(true);

    Logf(2, "running in standalone open-source mode");

    std::cout << "Femboi Firewall running in standalone mode. hwid=" << MachineHwid()
              << " ports=" << cfg.ports.size() << std::endl;

    std::vector<std::thread> workers;
    workers.emplace_back(MaintenanceThread, std::ref(st));

    std::atomic<uint64_t> dpi_drops{0};
    if (cfg.dpi_enabled) {
        if (DpiAvailable()) {
            workers.emplace_back(RunDpiLoop, std::ref(st.cfg), std::ref(st.counters),
                                 std::ref(dpi_drops), std::ref(g_stop), cfg.dpi_queue);
            Logf(2, "DPI enabled on nfqueue %u", cfg.dpi_queue);
        } else {
            Logf(1, "DPI requested but not compiled");
        }
    }

    while (!g_stop.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        if (g_reload.exchange(false)) {
            Logf(2, "SIGHUP received, reloading config");
            Config fresh = st.cfg;
            std::string e2;
            // Reload the path the daemon was started with, not the hardcoded
            // default, so `-c FILE` keeps working across reloads.
            if (fresh.Load(config_path, &e2)) {
                st.cfg = fresh;
                // Fresh geo/datacenter data must be re-read on reload too.
                st.geo.Load(st.cfg.geoip_path, nullptr);
                st.asn.Init();
                ApplyAll(st, true);
            } else {
                Logf(1, "reload failed: %s", e2.c_str());
            }
        }
    }

    Logf(2, "shutting down");
    g_stop.store(true);
    for (auto& t : workers) {
        if (t.joinable()) t.join();
    }
    st.running.store(false);

    // Shutdown policy: leave the installed ruleset in place so protection is
    // continuous across `systemctl restart` and daemon crashes. The ruleset is
    // intentionally torn down only by an explicit `nft-flush` or `systemctl stop`
    // ExecStopPost. This avoids the restart/reload protection gap.
    Logf(2, "clean exit (ruleset retained)");
    return 0;
}

} // namespace

// Update configuration setting from CLI
int CmdSet(Config& cfg, const std::string& config_path,
           const std::string& key, const std::string& value) {
    auto parse_bool = [&](bool* out) {
        if (value == "1" || value == "on" || value == "true" || value == "yes") { *out = true; return true; }
        if (value == "0" || value == "off" || value == "false" || value == "no") { *out = false; return true; }
        return false;
    };
    auto parse_uint = [&](uint32_t* out) {
        if (value.empty()) return false;
        for (char c : value) {
            if (!isdigit((unsigned char)c)) return false;
        }
        *out = (uint32_t)strtoul(value.c_str(), nullptr, 10);
        return true;
    };

    bool ok = false;
    if (key == "enabled") ok = parse_bool(&cfg.enabled);
    else if (key == "datacenter_filter") ok = parse_bool(&cfg.datacenter_filter);
    else if (key == "geo_enabled") ok = parse_bool(&cfg.geo_enabled);
    else if (key == "auto_ban") ok = parse_bool(&cfg.auto_ban);
    else if (key == "dpi_enabled") ok = parse_bool(&cfg.dpi_enabled);
    else if (key == "xdp_enabled") ok = parse_bool(&cfg.xdp_enabled);
    else if (key == "per_ip_pps") ok = parse_uint(&cfg.per_ip_pps);
    else if (key == "rate_burst") ok = parse_uint(&cfg.rate_burst);
    else if (key == "ban_seconds") ok = parse_uint(&cfg.ban_seconds);
    else {
        std::cerr << "error: unknown setting '" << key << "'\n";
        return 2;
    }
    if (!ok) {
        std::cerr << "error: bad value '" << value << "' for " << key << "\n";
        return 2;
    }

    std::string err;
    if (!cfg.Save(config_path, &err)) {
        std::cerr << "error: could not write " << config_path << ": " << err << "\n";
        return 1;
    }
    std::cout << key << "=" << value << "\n";

    std::string out, e;
    if (run_argv({"systemctl", "reload", "femboi-firewall"}, &out, &e)) {
        std::cout << "reloaded\n";
    } else {
        std::cout << "saved\n";
    }
    return 0;
}

// Validate that path contains only safe alphanumeric/path characters and no directory traversal
bool IsSafeConfigPath(const std::string& path) {
    if (path.empty() || path.size() > 4096) return false;
    if (path.find('\0') != std::string::npos || path.find("..") != std::string::npos) return false;
    for (char c : path) {
        // Backslash is rejected: this is Linux-only, and allowing it lets path
        // separators on non-POSIX tooling slip through validation.
        if (!std::isalnum(static_cast<unsigned char>(c)) &&
            c != '/' && c != '.' && c != '-' && c != '_') {
            return false;
        }
    }
    return true;
}

/**
 * @brief Ban an IP address manually with optional duration and reason.
 * @param cfg Active firewall configuration.
 * @param rest Command-line arguments [ip, duration, reason].
 * @return 0 on success, non-zero error code on failure.
 */
int CmdBan(const Config& cfg, const std::vector<std::string>& rest) {
    if (rest.empty()) {
        std::cerr << "usage: femboi-firewall ban <ip> [secs]\n";
        return 2;
    }
    uint32_t ip = 0;
    if (!ParseIp(rest[0], &ip)) {
        std::cerr << "error: invalid IPv4 address: " << rest[0] << "\n";
        return 2;
    }
    // Refuse to blackhole loopback, link-local, multicast or the host's own
    // routable addresses: a fat-fingered ban must not lock the operator out.
    if (is_local_or_loopback_ipv4(ip) || (ntohl(ip) & 0xF0000000u) == 0xE0000000u) {
        std::cerr << "error: refusing to ban local/loopback/multicast address "
                  << FormatIp(ip) << "\n";
        return 2;
    }

    // `ban <ip> permanent` is the only way to request a permanent ban; a bare
    // zero or a negative duration is rejected rather than silently meaning
    // "permanent".
    int64_t ttl = cfg.ban_seconds;
    if (rest.size() > 1) {
        if (rest[1] == "permanent") {
            ttl = 0;
        } else {
            char* end = nullptr;
            ttl = strtoll(rest[1].c_str(), &end, 10);
            if (end == rest[1].c_str() || ttl <= 0) {
                std::cerr << "error: duration must be a positive number of seconds "
                             "(or `permanent`)\n";
                return 2;
            }
        }
    }
    const std::string reason = rest.size() > 2 ? rest[2] : "manual";

    Nft nft;
    std::string e2;
    if (!nft.AddBan(ip, ttl > 0 ? (uint32_t)ttl : 0, &e2)) {
        std::cerr << "error: nft: " << e2 << "\n";
        return 1;
    }
    std::cout << "banned " << FormatIp(ip)
              << (ttl > 0 ? " for " + std::to_string(ttl) + "s" : " permanently")
              << " (" << reason << ")\n";
    return 0;
}

/**
 * @brief Unban an IP address manually.
 * @param rest Command-line arguments [ip].
 * @return 0 on success, non-zero error code on failure.
 */
int CmdUnban(const std::vector<std::string>& rest) {
    if (rest.empty()) {
        std::cerr << "usage: femboi-firewall unban <ip>\n";
        return 2;
    }
    uint32_t ip = 0;
    if (!ParseIp(rest[0], &ip)) {
        std::cerr << "error: invalid IPv4 address: " << rest[0] << "\n";
        return 2;
    }
    Nft nft;
    std::string e2;
    nft.DelBan(ip, &e2);
    // Clear both enforcement tiers so a manual unban is immediate and durable.
    XdpMaps xdp;
    if (xdp.Open(kXdpPinDir, nullptr)) {
        xdp.UnblockIp(ip, nullptr);
    }
    std::cout << "unbanned " << FormatIp(ip) << "\n";
    return 0;
}

/**
 * @brief Update or delete geo-blocking rules for a country code.
 * @param cfg Active firewall configuration.
 * @param rest Command-line arguments [CC, action, max_pps, max_conns].
 * @return 0 on success, non-zero error code on failure.
 */
int CmdGeo(const Config& cfg, const std::vector<std::string>& rest) {
    if (rest.size() < 2) {
        std::cerr << "usage: femboi-firewall geo <CC> <allow|block|rate|attack> [max_pps] [max_conns]\n";
        return 2;
    }
    std::string cc = rest[0];
    for (auto& c : cc) c = (char)toupper((unsigned char)c);
    if (cc.size() != 2) {
        std::cerr << "error: country code must be 2 letters\n";
        return 2;
    }
    int action = kGeoAllow;
    bool is_remove = false;
    const std::string& a = rest[1];
    if (a == "block") action = kGeoBlock;
    else if (a == "rate") action = kGeoRateLimit;
    else if (a == "attack") action = kGeoUnderAttack;
    else if (a == "remove" || a == "delete") is_remove = true;
    else if (a != "allow") {
        std::cerr << "error: invalid geo action\n";
        return 2;
    }

    std::map<std::string, CountryRule> rules;
    LoadGeoRules(cfg.rules_path, rules);
    if (is_remove) {
        rules.erase(cc);
    } else {
        CountryRule r;
        r.code = cc;
        auto prev = rules.find(cc);
        r.name = prev != rules.end() ? prev->second.name : cc;
        r.action = action;
        r.max_pps = rest.size() > 2 ? (uint32_t)strtoul(rest[2].c_str(), nullptr, 10) : 0;
        r.max_connections = rest.size() > 3 ? (uint32_t)strtoul(rest[3].c_str(), nullptr, 10) : 0;
        rules[cc] = r;
    }

    mkdir(cfg.state_dir.c_str(), 0700);
    std::ofstream out(cfg.rules_path, std::ios::trunc);
    if (!out) {
        std::cerr << "error: cannot write " << cfg.rules_path << "\n";
        return 1;
    }
    out << "[\n";
    bool first = true;
    for (const auto& kv : rules) {
        if (!first) out << ",\n";
        first = false;
        out << "  {\n"
            << "    \"code\": \"" << kv.second.code << "\",\n"
            << "    \"name\": \"" << (kv.second.name.empty() ? kv.second.code : kv.second.name) << "\",\n"
            << "    \"action\": " << kv.second.action << ",\n"
            << "    \"max_pps\": " << kv.second.max_pps << ",\n"
            << "    \"max_conns\": " << kv.second.max_connections << ",\n"
            << "    \"block_udp\": " << (kv.second.block_udp ? "true" : "false") << "\n"
            << "  }";
    }
    out << "\n]\n";
    out.close();

    std::cout << cc << " -> " << a << "\n";
    return 0;
}

/**
 * @brief Dispatch administrative commands requiring elevated root privileges.
 * @param command Subcommand name (list, ban, unban, geo).
 * @param cfg Active firewall configuration.
 * @param rest Remaining command-line arguments.
 * @return 0 on success, non-zero error code on failure.
 */
int CmdAdmin(const std::string& command, const Config& cfg, const std::vector<std::string>& rest) {
    if (geteuid() != 0) {
        std::cerr << "error: command needs root\n";
        return 1;
    }
    if (command == "list") return CmdList(cfg);
    if (command == "ban") return CmdBan(cfg, rest);
    if (command == "unban") return CmdUnban(rest);
    if (command == "geo") return CmdGeo(cfg, rest);
    return 2;
}

// Dispatch core operational commands
int CmdDispatch(const std::string& command, Config& cfg, const std::string& config_path, const std::vector<std::string>& rest) {
    if (command == "apply") {
        EngineState st;
        st.cfg = cfg;
        st.asn.Init();
        st.geo.Load(cfg.geoip_path, nullptr);
        return ApplyAll(st, true) ? 0 : 1;
    }
    if (command == "status") {
        // Report the real enforcement state: the table is present iff a ruleset
        // is installed, which is what "engine running" means here.
        Nft probe;
        std::string perr;
        const bool up = cfg.enabled && !probe.Dump(&perr).empty();
        return CmdStatus(cfg, BanTable{}, up);
    }
    if (command == "ports") {
        return CmdPorts(cfg);
    }
    if (command == "ruleset") {
        // Print the generated nftables script so it can be validated with
        // `nft -c -f -` (dry-run) in CI or by an operator before applying.
        Nft nft;
        std::cout << nft.BuildScript(cfg);
        return 0;
    }
    if (command == "set") {
        if (rest.size() < 2) {
            std::cerr << "usage: femboi-firewall set <key> <value>\n";
            return 2;
        }
        if (geteuid() != 0) {
            std::cerr << "error: set needs root\n";
            return 1;
        }
        return CmdSet(cfg, config_path, rest[0], rest[1]);
    }
    if (command == "daemon") {
        return CmdDaemon(cfg, config_path);
    }
    if (command == "list" || command == "ban" || command == "unban" || command == "geo") {
        return CmdAdmin(command, cfg, rest);
    }

    std::cerr << "unknown command: " << command << "\n\n";
    Usage();
    return 2;
}

} // namespace femboifw

// Program main entrypoint
int main(int argc, char** argv) {
    using namespace femboifw;

    std::string config_path = kDefaultConfig;
    std::string command;
    std::vector<std::string> rest;

    int i = 1;
    while (i < argc) {
        const std::string a = argv[i];
        if (a == "-h" || a == "--help") {
            Usage();
            return 0;
        } else if (a == "-c" || a == "--config") {
            if (i + 1 >= argc) {
                std::cerr << "error: " << a << " needs a path\n";
                return 2;
            }
            config_path = argv[++i];
        } else if (a == "-v" || a == "--verbose") {
            LogSetLevel(3);
        } else if (a == "-q" || a == "--quiet") {
            LogSetLevel(1);
        } else if (command.empty()) {
            command = a;
        } else {
            rest.push_back(a);
        }
        ++i;
    }

    if (command.empty()) {
        Usage();
        return 2;
    }

    if (config_path.empty() || config_path.find("..") != std::string::npos || !IsSafeConfigPath(config_path)) {
        std::cerr << "error: invalid characters or directory traversal in config path\n";
        return 2;
    }

    char resolved_cfg[PATH_MAX];
    if (realpath(config_path.c_str(), resolved_cfg) == nullptr) {
        if (config_path != kDefaultConfig) {
            std::cerr << "error: config file not found or inaccessible: " << config_path << "\n";
            return 2;
        }
    } else {
        config_path = resolved_cfg;
    }

    if (command == "doctor") return CmdDoctor();
    if (command == "hwid") {
        std::cout << MachineHwid() << "\n";
        return 0;
    }
    if (command == "nft-flush") {
        return Nft::FlushAll() ? 0 : 1;
    }

    Config cfg;
    cfg.ApplyDefaults();
    std::string err;
    if (!cfg.Load(config_path, &err)) {
        Logf(1, "config: %s (using defaults)", err.c_str());
    } else {
        LogSetFile(kDefaultLog);
    }

    return CmdDispatch(command, cfg, config_path, rest);
}
