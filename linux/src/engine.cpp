// Femboi Firewall engine
#include "fw.hpp"
#include "fw_portable.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <utility>

namespace femboifw {

// Port type string representation
const char* port_type_name(int type) {
    switch (type) {
        case kPortGame: return "Game";
        case kPortWeb: return "Web";
        case kPortSystem: return "System";
        default: return "Unknown";
    }
}

// Protocol string representation
const char* port_proto_name(int proto) {
    switch (proto) {
        case kProtoTcp: return "tcp";
        case kProtoUdp: return "udp";
        default: return "both";
    }
}

// Check standard web port numbers
static bool is_web_port_number(uint16_t p) {
    return p == 80 || p == 443 || p == 8080 || p == 8443 ||
           p == 8880 || p == 4443 || p == 9443;
}

// Automatically classify port type
int port_auto_classify(uint16_t port) {
    if (is_system_port(port)) return kPortSystem;
    if (is_web_port_number(port)) return kPortWeb;
    if (port >= 27015 && port <= 27050) return kPortGame;
    if (port == 27005 || port == 27020 || port == 27021) return kPortGame;
    return kPortGame;
}

// Sum all blocked counter types
uint64_t Counters::total_blocked() const {
    return blocked_ratelimit.load() + blocked_exploit.load() + blocked_syn.load() +
           blocked_banned.load() + blocked_small.load() + blocked_invalid.load() +
           blocked_a2s.load() + blocked_tcp.load() + blocked_tcp_payload.load();
}

// Populate default configuration values
void Config::ApplyDefaults() {
    ports.assign(kMaxPorts, PortSlot{});
    const uint16_t kSeedPorts[] = {27015, 27016, 80, 443, 8080};
    for (int i = 0; i < 5; ++i) {
        ports[i].port = kSeedPorts[i];
        ports[i].enabled = true;
        ports[i].type = port_auto_classify(kSeedPorts[i]);
        ports[i].attack = false;
        ports[i].rate_limit = 100;
        ports[i].speed_mbps = 10000;
        ports[i].proto = kProtoBoth;
    }
}

namespace {

// Trim leading and trailing whitespace
std::string trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return "";
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

} // namespace

// Load configuration from file
bool Config::Load(const std::string& path, std::string* err) {
    ApplyDefaults();

    std::ifstream in(path);
    if (!in) {
        if (err) *err = "config not found: " + path;
        return false;
    }

    std::string line;
    int slot = 0;
    bool saw_ports = false;

    while (std::getline(in, line)) {
        std::string t = trim(line);
        if (t.empty() || t[0] == '#' || t[0] == ';') continue;

        size_t eq = t.find('=');
        if (eq == std::string::npos) continue;
        const std::string key = trim(t.substr(0, eq));
        const std::string val = trim(t.substr(eq + 1));

        if (key == "ports") {
            saw_ports = true;
            ports.assign(kMaxPorts, PortSlot{});
            std::stringstream ss(val);
            std::string item;
            int idx = 0;
            while (std::getline(ss, item, ',') && idx < kMaxPorts) {
                item = trim(item);
                if (item.empty()) continue;
                uint16_t p = 0;
                std::string proto = "both";
                size_t slash = item.find('/');
                std::string port_part = slash == std::string::npos ? item : item.substr(0, slash);
                if (slash != std::string::npos) proto = trim(item.substr(slash + 1));

                char* end = nullptr;
                long n = strtol(port_part.c_str(), &end, 10);
                if (end == port_part.c_str() || n <= 0 || n > 65535) continue;
                p = (uint16_t)n;

                PortSlot& s = ports[idx++];
                s.port = p;
                s.enabled = true;
                s.type = port_auto_classify(p);
                s.rate_limit = 100;
                s.speed_mbps = 10000;
                if (proto == "tcp") s.proto = kProtoTcp;
                else if (proto == "udp") s.proto = kProtoUdp;
                else s.proto = kProtoBoth;
            }
            continue;
        }

        if (key.rfind("slot", 0) == 0) {
            std::stringstream ss(val);
            unsigned port = 0, enabled = 0, type = 0, attack = 0,
                     rate = 100, speed = 10000, proto = 0;
            ss >> port >> enabled >> type >> attack >> rate >> speed >> proto;
            if (port == 0 || port > 65535) continue;
            if (!saw_ports) ports.assign(kMaxPorts, PortSlot{});
            PortSlot s;
            s.port = (uint16_t)port;
            s.enabled = enabled != 0;
            s.type = (type <= 2) ? (int)type : port_auto_classify(s.port);
            s.attack = attack != 0;
            s.rate_limit = (rate >= 10 && rate <= 500) ? rate : 100;
            s.speed_mbps = speed;
            s.proto = (proto <= 2) ? (int)proto : kProtoBoth;
            if (slot < kMaxPorts) ports[slot++] = s;
            continue;
        }

        if (key == "enabled") enabled = (val == "1" || val == "true" || val == "yes");
        else if (key == "datacenter_filter") datacenter_filter = (val != "0" && val != "false");
        else if (key == "geo_enabled") geo_enabled = (val != "0" && val != "false");
        else if (key == "cti_enabled") cti_enabled = (val != "0" && val != "false");
        else if (key == "auto_ban") auto_ban = (val != "0" && val != "false");
        else if (key == "ban_seconds") ban_seconds = (uint32_t)strtoul(val.c_str(), nullptr, 10);
        else if (key == "per_ip_pps") per_ip_pps = (uint32_t)strtoul(val.c_str(), nullptr, 10);
        else if (key == "rate_burst") rate_burst = (uint32_t)strtoul(val.c_str(), nullptr, 10);
        else if (key == "dpi_enabled") dpi_enabled = (val != "0" && val != "false");
        else if (key == "dpi_queue") dpi_queue = (uint16_t)strtoul(val.c_str(), nullptr, 10);
        else if (key == "xdp_enabled") xdp_enabled = (val != "0" && val != "false");
        else if (key == "xdp_pin_dir") xdp_pin_dir = val;
        else if (key == "geoip_path") geoip_path = val;
        else if (key == "rules_path") rules_path = val;
        else if (key == "state_dir") state_dir = val;
    }

    if (ban_seconds < 60) ban_seconds = 60;
    if (per_ip_pps < 10) per_ip_pps = 10;
    return true;
}

// Persist configuration to file
bool Config::Save(const std::string& path, std::string* err) const {
    const std::string tmp = path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::trunc);
        if (!out) {
            if (err) *err = "cannot write " + tmp;
            return false;
        }
        out << "# Femboi Firewall configuration\n"
            << "# Ports format: port/proto comma separated\n"
            << "# System ports are exempted\n\n";

        out << "enabled=" << (enabled ? 1 : 0) << "\n";
        out << "ports=";
        bool first = true;
        for (const auto& s : ports) {
            if (!s.enabled || s.port == 0) continue;
            if (!first) out << ",";
            out << s.port << "/" << port_proto_name(s.proto);
            first = false;
        }
        out << "\n\n";

        out << "# Filtering\n";
        out << "datacenter_filter=" << (datacenter_filter ? 1 : 0) << "\n";
        out << "geo_enabled=" << (geo_enabled ? 1 : 0) << "\n";
        out << "cti_enabled=" << (cti_enabled ? 1 : 0) << "\n";
        out << "auto_ban=" << (auto_ban ? 1 : 0) << "\n";
        out << "ban_seconds=" << ban_seconds << "\n";
        out << "per_ip_pps=" << per_ip_pps << "\n";
        out << "rate_burst=" << rate_burst << "\n\n";

        out << "# Userspace DPI\n";
        out << "dpi_enabled=" << (dpi_enabled ? 1 : 0) << "\n";
        out << "dpi_queue=" << dpi_queue << "\n\n";

        out << "# XDP Datapath\n";
        out << "xdp_enabled=" << (xdp_enabled ? 1 : 0) << "\n";
        out << "xdp_pin_dir=" << xdp_pin_dir << "\n\n";

        out << "# Paths\n";
        out << "geoip_path=" << geoip_path << "\n";
        out << "rules_path=" << rules_path << "\n";
        out << "state_dir=" << state_dir << "\n";
    }

    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        if (err) *err = "cannot replace " + path;
        return false;
    }
    return true;
}

// Load binary GeoIP database
bool GeoDb::Load(const std::string& path, std::string* err) {
    ranges_.clear();

    std::ifstream in(path, std::ios::binary);
    if (!in) {
        if (err) *err = "geoip not found: " + path;
        return false;
    }

    char magic[4] = {0};
    in.read(magic, 4);
    if (!in || memcmp(magic, "GEO1", 4) != 0) {
        if (err) *err = "bad geoip magic (expected GEO1): " + path;
        return false;
    }

    uint32_t count = 0;
    in.read(reinterpret_cast<char*>(&count), 4);

    if (count == 0 || count > 2000000) {
        if (err) *err = "implausible geoip record count";
        return false;
    }

    struct __attribute__((packed)) FileEntry {
        uint32_t start_ip;
        uint32_t end_ip;
        char cc[2];
    };

    std::vector<FileEntry> raw(count);
    in.read(reinterpret_cast<char*>(raw.data()), (std::streamsize)count * 10);
    if ((size_t)in.gcount() != (size_t)count * 10) {
        if (err) *err = "truncated geoip file";
        return false;
    }

    ranges_.reserve(count);
    for (const auto& e : raw) {
        Range r;
        r.start_ip = e.start_ip;
        r.end_ip = e.end_ip;
        r.cc[0] = e.cc[0];
        r.cc[1] = e.cc[1];
        r.cc[2] = '\0';
        ranges_.push_back(r);
    }
    std::sort(ranges_.begin(), ranges_.end(),
              [](const Range& a, const Range& b) { return a.start_ip < b.start_ip; });

    Logf(2, "geoip: loaded %zu ranges from %s", ranges_.size(), path.c_str());
    return true;
}

// Look up 2-letter country code
const char* GeoDb::Lookup(uint32_t ip_host) const {
    if (ranges_.empty()) return "XX";
    size_t low = 0, high = ranges_.size();
    while (low < high) {
        size_t mid = low + (high - low) / 2;
        const Range& r = ranges_[mid];
        if (ip_host >= r.start_ip && ip_host <= r.end_ip) return r.cc;
        if (ip_host < r.start_ip) high = mid;
        else low = mid + 1;
    }
    return "XX";
}

namespace {

struct CidrSeed {
    const char* cidr;
};

// Seed datacenter CIDR list
const CidrSeed kSeedCidrs[] = {
    {"5.9.0.0/16"}, {"49.12.0.0/16"}, {"65.108.0.0/16"}, {"65.109.0.0/16"},
    {"78.46.0.0/15"}, {"88.99.0.0/16"}, {"91.107.0.0/16"}, {"94.130.0.0/16"},
    {"95.216.0.0/15"}, {"116.202.0.0/16"}, {"116.203.0.0/16"}, {"128.140.0.0/16"},
    {"135.181.0.0/16"}, {"136.243.0.0/16"}, {"138.201.0.0/16"}, {"142.132.0.0/16"},
    {"144.76.0.0/16"}, {"148.251.0.0/16"}, {"157.90.0.0/16"}, {"159.69.0.0/16"},
    {"162.55.0.0/16"}, {"167.235.0.0/16"},
    {"5.135.0.0/16"}, {"5.196.0.0/16"}, {"46.105.0.0/16"}, {"51.38.0.0/16"},
    {"51.68.0.0/16"}, {"51.75.0.0/16"}, {"51.77.0.0/16"}, {"51.79.0.0/16"},
    {"51.83.0.0/16"}, {"51.89.0.0/16"}, {"51.91.0.0/16"}, {"51.161.0.0/16"},
    {"51.178.0.0/16"}, {"51.195.0.0/16"}, {"51.210.0.0/16"}, {"51.222.0.0/16"},
    {"51.254.0.0/16"}, {"54.36.0.0/16"}, {"54.37.0.0/16"}, {"54.38.0.0/16"},
    {"54.39.0.0/16"}, {"91.121.0.0/16"}, {"92.222.0.0/16"}, {"94.23.0.0/16"},
    {"137.74.0.0/16"}, {"141.94.0.0/16"}, {"145.239.0.0/16"}, {"147.135.0.0/16"},
    {"149.202.0.0/16"}, {"151.80.0.0/16"}, {"158.69.0.0/16"}, {"164.132.0.0/16"},
    {"167.114.0.0/16"}, {"178.32.0.0/15"}, {"188.165.0.0/16"}, {"192.95.0.0/16"},
    {"193.70.0.0/16"}, {"198.27.0.0/16"}, {"198.50.0.0/16"},
    {"24.199.64.0/18"}, {"45.55.0.0/16"}, {"64.225.0.0/16"}, {"64.227.0.0/16"},
    {"68.183.0.0/16"}, {"104.131.0.0/16"}, {"104.236.0.0/16"}, {"107.170.0.0/16"},
    {"128.199.0.0/16"}, {"138.68.0.0/16"}, {"138.197.0.0/16"}, {"142.93.0.0/16"},
    {"143.198.0.0/16"}, {"144.126.0.0/16"}, {"146.190.0.0/16"}, {"157.245.0.0/16"},
    {"159.65.0.0/16"}, {"159.89.0.0/16"}, {"161.35.0.0/16"}, {"165.22.0.0/16"},
    {"165.227.0.0/16"}, {"167.71.0.0/16"}, {"167.172.0.0/16"}, {"174.138.0.0/16"},
    {"178.62.0.0/16"}, {"178.128.0.0/16"}, {"188.166.0.0/16"}, {"206.189.0.0/16"},
    {"45.32.0.0/16"}, {"45.63.0.0/16"}, {"45.76.0.0/16"}, {"64.176.0.0/16"},
    {"66.42.0.0/16"}, {"95.179.128.0/17"}, {"108.61.0.0/16"}, {"140.82.0.0/16"},
    {"144.202.0.0/16"}, {"149.28.0.0/16"}, {"155.138.128.0/17"}, {"158.247.0.0/16"},
    {"207.148.0.0/16"}, {"216.128.128.0/18"}, {"217.69.0.0/17"},
    {"23.92.16.0/20"}, {"45.33.0.0/16"}, {"45.56.0.0/16"}, {"45.79.0.0/16"},
    {"50.116.0.0/16"}, {"66.228.32.0/19"}, {"69.164.192.0/18"}, {"96.126.96.0/19"},
    {"97.107.128.0/17"}, {"139.144.0.0/16"}, {"139.162.0.0/16"}, {"143.42.0.0/16"},
    {"172.104.0.0/15"}, {"172.234.0.0/16"}, {"173.230.128.0/17"}, {"173.255.192.0/18"},
    {"194.195.192.0/18"},
    {"5.189.128.0/18"}, {"38.242.128.0/18"}, {"62.171.128.0/18"}, {"79.143.176.0/20"},
    {"144.91.64.0/18"}, {"161.97.64.0/18"}, {"167.86.64.0/18"}, {"173.212.192.0/18"},
    {"185.209.160.0/19"}, {"194.164.192.0/18"}, {"207.180.192.0/18"},
    {"5.79.64.0/18"}, {"37.58.48.0/20"}, {"46.243.0.0/18"}, {"64.86.0.0/16"},
    {"66.90.64.0/18"}, {"85.17.0.0/16"}, {"95.211.0.0/16"}, {"108.62.0.0/16"},
    {"209.58.128.0/17"},
    {"37.120.128.0/17"}, {"45.83.104.0/21"}, {"45.153.160.0/19"}, {"80.240.16.0/20"},
    {"89.187.160.0/19"}, {"92.223.0.0/17"}, {"138.199.0.0/16"}, {"146.70.0.0/16"},
    {"152.89.96.0/19"}, {"154.47.16.0/20"}, {"156.146.32.0/19"}, {"185.152.64.0/22"},
    {"185.220.100.0/22"}, {"185.234.216.0/22"}, {"194.36.16.0/22"}, {"195.181.160.0/19"},
    {"204.152.216.0/22"}, {"217.138.192.0/18"},
    {"43.128.0.0/14"}, {"43.132.0.0/14"}, {"43.152.0.0/14"}, {"47.74.0.0/15"},
    {"47.76.0.0/14"}, {"47.88.0.0/14"}, {"47.240.0.0/14"}, {"47.244.0.0/14"},
    {"119.28.0.0/15"}, {"129.226.0.0/16"}, {"150.109.0.0/16"},
};

// Parse CIDR block string
void add_cidr(std::vector<std::pair<uint32_t, uint32_t>>& out,
              const std::string& cidr_text) {
    std::string s = trim(cidr_text);
    if (s.empty() || s[0] == '#') return;

    int prefix = 32;
    size_t slash = s.find('/');
    std::string ip_part = s;
    if (slash != std::string::npos) {
        ip_part = s.substr(0, slash);
        char* end = nullptr;
        long p = strtol(s.c_str() + slash + 1, &end, 10);
        if (end == s.c_str() + slash + 1 || p < 0 || p > 32) return;
        prefix = (int)p;
    }

    uint32_t base_nbo = 0;
    if (!ParseIp(ip_part, &base_nbo)) return;
    uint32_t base = ntohl(base_nbo);

    uint32_t mask = prefix >= 32 ? 0xFFFFFFFFu
                   : (prefix == 0 ? 0u : (0xFFFFFFFFu << (32 - prefix)));
    out.emplace_back(base & mask, (base & mask) | ~mask);
}

// Sort and merge overlapping ranges
void sort_and_merge(std::vector<std::pair<uint32_t, uint32_t>>& v) {
    std::sort(v.begin(), v.end());
    std::vector<std::pair<uint32_t, uint32_t>> merged;
    merged.reserve(v.size());
    for (const auto& r : v) {
        if (!merged.empty() && r.first <= merged.back().second) {
            if (r.second > merged.back().second) merged.back().second = r.second;
            continue;
        }
        merged.push_back(r);
    }
    v.swap(merged);
}

} // namespace

// Initialize ASN filter ranges
void AsnFilter::Init() {
    std::vector<std::pair<uint32_t, uint32_t>> ranges;
    ranges.reserve(256);
    for (const auto& s : kSeedCidrs) add_cidr(ranges, s.cidr);

    std::ifstream in("/etc/femboi/datacenter.cidr");
    if (in) {
        std::string line;
        size_t extra = 0;
        while (std::getline(in, line)) {
            size_t before = ranges.size();
            add_cidr(ranges, line);
            if (ranges.size() != before) ++extra;
        }
        if (extra) Logf(2, "datacenter.cidr: added %zu operator ranges", extra);
    }

    sort_and_merge(ranges);
    ranges_ = std::move(ranges);
    Logf(2, "asn filter: %zu merged datacenter ranges", ranges_.size());
}

// Check if IP matches datacenter range
bool AsnFilter::IsDatacenter(uint32_t ip_nbo) const {
    if (!enabled_ || ranges_.empty()) return false;
    const uint32_t ip = ntohl(ip_nbo);
    if (is_local_or_loopback_ipv4(ip_nbo)) return false;

    size_t left = 0, right = ranges_.size();
    while (left < right) {
        size_t mid = left + (right - left) / 2;
        const auto& r = ranges_[mid];
        if (ip >= r.first && ip <= r.second) return true;
        if (ip < r.first) right = mid;
        else left = mid + 1;
    }
    return false;
}

// Add IP to ban table
void BanTable::Add(uint32_t ip_nbo, uint16_t port, const std::string& reason,
                   int64_t duration_secs, int count, bool manual) {
    if (duration_secs > 0 && duration_secs < 60) duration_secs = 60;

    std::lock_guard<std::mutex> lk(mu_);
    const int64_t now = NowEpoch();
    const int64_t expires = duration_secs > 0 ? now + duration_secs : 0;

    auto it = bans_.find(ip_nbo);
    if (it != bans_.end()) {
        it->second.count += count;
        if (it->second.expires_at == 0) return;
        if (expires == 0) {
            it->second.expires_at = 0;
        } else if (expires > it->second.expires_at) {
            it->second.expires_at = expires;
        }
        if (manual) it->second.manual = true;
        return;
    }

    BanEntry e;
    e.ip_nbo = ip_nbo;
    e.ip_str = FormatIp(ip_nbo);
    e.port = port;
    e.reason = reason;
    e.expires_at = expires;
    e.count = count;
    e.manual = manual;
    bans_[ip_nbo] = e;
}

// Remove IP from ban table
bool BanTable::Remove(uint32_t ip_nbo) {
    std::lock_guard<std::mutex> lk(mu_);
    return bans_.erase(ip_nbo) > 0;
}

// Check if IP is currently banned
bool BanTable::Contains(uint32_t ip_nbo, int64_t now) const {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = bans_.find(ip_nbo);
    if (it == bans_.end()) return false;
    return it->second.expires_at == 0 || it->second.expires_at > now;
}

// Expire outdated bans
void BanTable::Sweep(int64_t now) {
    std::lock_guard<std::mutex> lk(mu_);
    for (auto it = bans_.begin(); it != bans_.end();) {
        if (it->second.expires_at != 0 && it->second.expires_at <= now) {
            it = bans_.erase(it);
        } else {
            ++it;
        }
    }
}

// Snapshot active bans
std::vector<BanEntry> BanTable::Snapshot(int64_t now, size_t limit) const {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<BanEntry> out;
    out.reserve(std::min(limit, bans_.size()));
    for (const auto& kv : bans_) {
        if (kv.second.expires_at == 0 || kv.second.expires_at > now) {
            out.push_back(kv.second);
            if (out.size() >= limit) break;
        }
    }
    std::sort(out.begin(), out.end(), [](const BanEntry& a, const BanEntry& b) {
        return a.expires_at < b.expires_at;
    });
    return out;
}

// Return active banned IP set
std::set<uint32_t> BanTable::ActiveSet(int64_t now) const {
    std::lock_guard<std::mutex> lk(mu_);
    std::set<uint32_t> out;
    for (const auto& kv : bans_) {
        if (kv.second.expires_at == 0 || kv.second.expires_at > now) {
            out.insert(kv.first);
        }
    }
    return out;
}

// Total number of entries in ban table
size_t BanTable::size() const {
    std::lock_guard<std::mutex> lk(mu_);
    return bans_.size();
}

// Clear all bans
void BanTable::Clear() {
    std::lock_guard<std::mutex> lk(mu_);
    bans_.clear();
}

} // namespace femboifw
