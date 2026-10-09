#pragma once
// Femboi Firewall Linux engine
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace femboifw {

// Port configuration model
constexpr int kMaxPorts = 32;

enum PortType {
    kPortGame = 0,
    kPortWeb = 1,
    kPortSystem = 2,
};

enum PortProto {
    kProtoBoth = 0,
    kProtoTcp = 1,
    kProtoUdp = 2,
};

struct PortSlot {
    uint16_t port = 0;
    bool enabled = false;
    int type = kPortGame;
    bool attack = false;
    uint32_t rate_limit = 100;
    uint32_t speed_mbps = 0;
    int proto = kProtoBoth;
};

const char* port_type_name(int type);
const char* port_proto_name(int proto);
int port_auto_classify(uint16_t port);

// Packet and attack counters
struct Counters {
    std::atomic<uint64_t> processed{0};
    std::atomic<uint64_t> passed{0};
    std::atomic<uint64_t> blocked_ratelimit{0};
    std::atomic<uint64_t> blocked_exploit{0};
    std::atomic<uint64_t> blocked_syn{0};
    std::atomic<uint64_t> blocked_banned{0};
    std::atomic<uint64_t> blocked_small{0};
    std::atomic<uint64_t> blocked_invalid{0};
    std::atomic<uint64_t> blocked_a2s{0};
    std::atomic<uint64_t> blocked_tcp{0};
    std::atomic<uint64_t> blocked_tcp_payload{0};

    uint64_t total_blocked() const;
};

struct BlockEvent {
    std::string ip;
    uint16_t port = 0;
    std::string type;
    std::string reason;
    int count = 1;
    int64_t at = 0;
};

struct BanEntry {
    uint32_t ip_nbo = 0;
    std::string ip_str;
    uint16_t port = 0;
    std::string reason;
    int64_t expires_at = 0;
    int count = 1;
    bool manual = false;
};

// Main configuration structure
struct Config {
    bool enabled = true;
    std::vector<PortSlot> ports;

    bool datacenter_filter = true;
    bool geo_enabled = true;

    // Trusted source addresses/CIDRs exempt from rate limits and auto-ban.
    std::vector<std::string> whitelist;
    bool auto_ban = true;
    uint32_t ban_seconds = 3600;
    uint32_t per_ip_pps = 400;
    uint32_t rate_burst = 800;

    // Optional userspace DPI
    bool dpi_enabled = false;
    uint16_t dpi_queue = 200;

    // Optional XDP datapath
    bool xdp_enabled = false;
    std::string xdp_pin_dir = "/sys/fs/bpf/femboifw";

    std::string geoip_path = "/usr/share/femboi/geoip.dat";
    std::string rules_path = "/etc/femboi/geo_rules.json";
    std::string state_dir = "/var/lib/femboi";

    bool Load(const std::string& path, std::string* err);
    bool Save(const std::string& path, std::string* err) const;
    void ApplyDefaults();
};

// Geo-blocking rules
enum GeoAction {
    kGeoAllow = 0,
    kGeoBlock = 1,
    kGeoRateLimit = 2,
    kGeoUnderAttack = 3,
};

struct CountryRule {
    std::string code;
    std::string name;
    int action = kGeoAllow;
    uint32_t max_pps = 0;
    uint32_t max_connections = 0;
    bool block_udp = false;
};

// GeoIP binary reader
class GeoDb {
public:
    bool Load(const std::string& path, std::string* err);
    bool loaded() const { return !ranges_.empty(); }
    size_t size() const { return ranges_.size(); }

    const char* Lookup(uint32_t ip_host) const;

    struct Range {
        uint32_t start_ip;
        uint32_t end_ip;
        char cc[3];
    };
    const std::vector<Range>& ranges() const { return ranges_; }

private:
    std::vector<Range> ranges_;
};

// Datacenter ASN filter
class AsnFilter {
public:
    void Init();
    bool IsDatacenter(uint32_t ip_nbo) const;
    bool enabled() const { return enabled_; }
    void set_enabled(bool v) { enabled_ = v; }
    size_t range_count() const { return ranges_.size(); }
    const std::vector<std::pair<uint32_t, uint32_t>>& ranges() const { return ranges_; }

private:
    std::vector<std::pair<uint32_t, uint32_t>> ranges_;
    bool enabled_ = true;
};

// Active ban table
class BanTable {
public:
    void Add(uint32_t ip_nbo, uint16_t port, const std::string& reason,
             int64_t duration_secs, int count = 1, bool manual = false);

    // Hard upper bound; the oldest expiring entry is evicted when exceeded so
    // a spoofed-source ban flood cannot grow the table without limit.
    static constexpr size_t kMaxEntries = 131072;
    bool Remove(uint32_t ip_nbo);
    bool Contains(uint32_t ip_nbo, int64_t now) const;
    void Sweep(int64_t now);
    std::vector<BanEntry> Snapshot(int64_t now, size_t limit) const;
    std::set<uint32_t> ActiveSet(int64_t now) const;
    size_t size() const;
    void Clear();

    // --- Durable store -----------------------------------------------------
    // Userspace is the single source of truth for bans; the nft set and the XDP
    // blacklist are derived views. The store survives daemon restart and reload.
    void SetStorePath(const std::string& path);
    bool Persist() const;   // write the active table to the store
    bool Restore();         // load the store into the active table

private:
    void PersistLocked() const;

    mutable std::mutex mu_;
    std::unordered_map<uint32_t, BanEntry> bans_;
    std::string store_path_;
};

// nftables management class
class Nft {
public:
    static constexpr const char* kTable = "femboifw";
    static constexpr const char* kFamily = "inet";

    bool EnsureBase(const Config& cfg, std::string* err);
    // Generate the nftables ruleset script (without applying it).
    std::string BuildScript(const Config& cfg);
    static bool FlushAll();

    bool AddBan(uint32_t ip_nbo, uint32_t ttl_secs, std::string* err = nullptr);
    bool DelBan(uint32_t ip_nbo, std::string* err = nullptr);
    bool SyncBanSet(const std::set<uint32_t>& ips, std::string* err = nullptr);

    // Trusted sources (addresses/CIDRs) that bypass limits and auto-ban.
    bool SyncWhitelist(const std::vector<std::string>& entries, std::string* err = nullptr);

    bool SetGeoBlocks(const std::vector<std::pair<uint32_t, uint32_t>>& ranges,
                      std::string* err = nullptr);
    bool SetGeoRateLimits(const std::vector<std::pair<uint32_t, uint32_t>>& ranges,
                          std::string* err = nullptr);
    bool SetDatacenterBlocks(const std::vector<std::pair<uint32_t, uint32_t>>& ranges,
                            std::string* err = nullptr);

    std::string Dump(std::string* err = nullptr) const;

    static bool Available();
    static bool Run(const std::vector<std::string>& args, std::string* out, std::string* err);
    static bool RunScript(const std::string& script, std::string* out, std::string* err);
};

// NFQueue DPI packet inspection.
// The config is passed as an immutable shared snapshot: the DPI thread owns a
// reference for its whole lifetime, so a SIGHUP reload that swaps the daemon's
// config cannot race with or free the object out from under the reader.
bool DpiAvailable();
void RunDpiLoop(std::shared_ptr<const Config> cfg, Counters& counters,
                std::atomic<uint64_t>& drops, std::atomic<bool>& stop,
                uint16_t queue_num);

// --- Userspace, handshake-gated auto-ban -----------------------------------
// Subscribes to kernel conntrack events and only escalates a source to a ban
// AFTER it completes a TCP handshake (conntrack reaches ESTABLISHED). A spoofed
// SYN never completes a handshake, so it can no longer blackhole a victim.
// Optional build feature (HAVE_CONNTRACK); stubbed out otherwise.
using BanCallback = std::function<bool(uint32_t ip_nbo, const std::string& reason)>;
bool ConntrackAvailable();
void RunConntrackLoop(std::shared_ptr<const Config> cfg, BanCallback on_ban,
                      std::atomic<bool>& stop);

// Host hardware identity
std::string MachineHwid();
std::string MachineName();

// Utility helpers
std::string Sha256File(const std::string& path);
int64_t NowEpoch();
std::string FormatIp(uint32_t ip_nbo);
bool ParseIp(const std::string& text, uint32_t* out_nbo);
std::string Hex8(uint32_t v);

void LogSetLevel(int level);
void LogSetFile(const std::string& path);
void Logf(int level, const char* fmt, ...) __attribute__((format(printf, 2, 3)));

} // namespace femboifw
