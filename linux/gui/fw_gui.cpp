// ===================================================================
// Fluxx Firewall — Linux desktop panel
//
// Port of windows-retired/gui.cpp, layout-faithful. Same window chrome, same
// header, same six tabs in the same order, same palette values, same widget
// idiom, same table columns and column widths, same Turkish labels.
//
// Where the Windows build read an in-process engine over a named pipe, this reads
// what the kernel and the config already hold:
//   counters  -> `nft -a list table inet fluxxfw`, split into passed (the rule
//                marked comment "passed") and blocked (every rule carrying drop)
//   bans      -> the `banned` set, which is what is actually being dropped
//   ports     -> the ports= line in /etc/femboi/firewall.conf
//   geo rules -> /etc/femboi/geo_rules.json, the same line-oriented file the
//                Windows GUI writes and the daemon reads
//   players   -> the game server plugin's per-instance snapshot
//
// Settings writes through `fluxxfw set <key> <value>` instead of editing the
// config itself: one writer for that file, and the daemon re-applies from its
// in-memory ban table so a change never releases the bans in force.
//
// Two Windows-only controls have no Linux counterpart and are therefore absent
// rather than present and dead: the "Speed Up" optimizer (a Windows kernel/stack
// tuner) and the licence/update box (the Linux build verifies at startup and has
// no self-update path). The Settings tab keeps the same box-and-button layout and
// spends it on the protections this build actually has.
//
// Platform layer: Win32 + DX11 -> GLFW + OpenGL3.
// ===================================================================
#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "proc.hpp"

#include <GLFW/glfw3.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>
#include <arpa/inet.h>
#include <netinet/in.h>

namespace {

// ---------------------------------------------------------------------------
// Palette — value-for-value from the Windows build.
// ---------------------------------------------------------------------------
ImVec4 ColBg0(10 / 255.f, 10 / 255.f, 15 / 255.f, 1.f);
ImVec4 ColBg1(18 / 255.f, 18 / 255.f, 26 / 255.f, 1.f);
ImVec4 ColBg2(26 / 255.f, 26 / 255.f, 38 / 255.f, 1.f);
ImVec4 ColBg3(34 / 255.f, 34 / 255.f, 50 / 255.f, 1.f);
ImVec4 ColText0(240 / 255.f, 240 / 255.f, 245 / 255.f, 1.f);
ImVec4 ColText1(160 / 255.f, 160 / 255.f, 184 / 255.f, 1.f);
ImVec4 ColText2(96 / 255.f, 96 / 255.f, 120 / 255.f, 1.f);
ImVec4 ColAccent(1.f, 51 / 255.f, 102 / 255.f, 1.f);
ImVec4 ColOk(46 / 255.f, 213 / 255.f, 115 / 255.f, 1.f);
ImVec4 ColBad(1.f, 71 / 255.f, 87 / 255.f, 1.f);
ImVec4 ColCyan(0.f, 210 / 255.f, 255 / 255.f, 1.f);
ImVec4 ColPps(0.f, 229 / 255.f, 160 / 255.f, 1.f);
ImVec4 ColBlocks(1.f, 120 / 255.f, 80 / 255.f, 1.f);
ImVec4 ColAmber(1.f, 184 / 255.f, 0.f, 1.f);
ImVec4 ColGlassBorder(1.f, 1.f, 1.f, 0.08f);

constexpr const char* kConfPath  = "/etc/femboi/firewall.conf";
constexpr const char* kRulesPath = "/etc/femboi/geo_rules.json";
constexpr const char* kFwBin     = "/usr/local/bin/femboi-firewall";

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------
enum PortProto { PROTO_BOTH = 0, PROTO_TCP = 1, PROTO_UDP = 2 };
enum PortType  { TYPE_GAME = 0, TYPE_WEB = 1 };

struct PortRow {
    int port = 0;
    std::string proto = "udp";
    int type = TYPE_GAME;
    bool attack = false;
    int rate_limit = 100;
    int speed_mbps = 10000;
    bool enabled = false;
};

struct BanRow {
    std::string ip;
    unsigned port = 0;
    long long remain_sec = 0;
    std::string reason;
};

struct CountryRule {
    std::string code;
    std::string name;
    int action = 0;           // 0 allow 1 block 2 rate 3 attack
    unsigned max_pps = 0;
    unsigned max_conns = 0;
    bool block_udp = false;
    unsigned long long rx_packets = 0;
    unsigned long long blocked_packets = 0;
};

struct Talker { std::string ip; unsigned long long bytes = 0; };
struct ClientRow { std::string ip_port; std::string pure_ip; std::string country = "--"; int server_port = 0; std::string state; int pps = 0; int idle_sec = 0; };

struct Snapshot {
    bool table_present = false;
    std::string machine;
    std::vector<PortRow> ports;
    std::vector<BanRow> bans;
    std::vector<CountryRule> geo_rules;
    std::vector<Talker> talkers;
    std::vector<ClientRow> clients;
    std::vector<std::string> recent_blocks;  // "ip  type"

    unsigned long long traffic = 0;
    unsigned long long passed = 0;
    unsigned long long blocked = 0;
    int players = 0;

    double timestamp = 0.0;
    float cur_pps = 0.0f;
    float cur_bps = 0.0f;
    std::map<int, unsigned long long> port_traffic;
    std::map<int, unsigned long long> port_blocked;
    std::map<int, float> port_cur_pps;

    std::vector<float> chart_pps, chart_blocks;

    struct MinuteStat {
        std::string minute;
        unsigned long long timestamp = 0;
        unsigned long long traffic = 0;
        unsigned long long blocked = 0;
    };
    std::vector<MinuteStat> minutes_60;

    int per_ip_pps = 0, rate_burst = 0, ban_seconds = 0;
    bool enabled = true, datacenter_filter = true, geo_enabled = true;
    bool cti_enabled = true, auto_ban = true, dpi_enabled = false, xdp_enabled = false;
};

// ---------------------------------------------------------------------------
// GeoIP Database Loader & Lookup (fast binary search over /usr/share/fluxxfw/geoip.dat)
// ---------------------------------------------------------------------------
struct GeoRange {
    uint32_t start_ip;
    uint32_t end_ip;
    char cc[3];
};

class SimpleGeo {
public:
    std::vector<GeoRange> ranges;
    bool loaded = false;

    bool Load(const std::string& path = "/usr/share/femboi/geoip.dat") {
        FILE* f = fopen(path.c_str(), "rb");
        if (!f) return false;
        char magic[4];
        if (fread(magic, 1, 4, f) != 4 || memcmp(magic, "GEO1", 4) != 0) {
            fclose(f);
            return false;
        }
        uint32_t count = 0;
        if (fread(&count, 4, 1, f) != 1 || count == 0 || count > 2000000) {
            fclose(f);
            return false;
        }
        struct __attribute__((packed)) RawEntry {
            uint32_t start_ip;
            uint32_t end_ip;
            char cc[2];
        };
        std::vector<RawEntry> raw(count);
        if (fread(raw.data(), 10, count, f) != count) {
            fclose(f);
            return false;
        }
        fclose(f);

        ranges.clear();
        ranges.reserve(count);
        for (const auto& e : raw) {
            GeoRange r;
            r.start_ip = e.start_ip;
            r.end_ip = e.end_ip;
            r.cc[0] = e.cc[0];
            r.cc[1] = e.cc[1];
            r.cc[2] = '\0';
            ranges.push_back(r);
        }
        std::sort(ranges.begin(), ranges.end(), [](const GeoRange& a, const GeoRange& b) {
            return a.start_ip < b.start_ip;
        });
        loaded = true;
        return true;
    }

    const char* Lookup(uint32_t ip_host) const {
        if (ranges.empty()) return "--";
        size_t low = 0, high = ranges.size();
        while (low < high) {
            size_t mid = low + (high - low) / 2;
            const auto& r = ranges[mid];
            if (ip_host >= r.start_ip && ip_host <= r.end_ip) return r.cc;
            if (ip_host < r.start_ip) high = mid;
            else low = mid + 1;
        }
        return "--";
    }

    const char* LookupStr(const std::string& ip_str) const {
        struct in_addr a;
        if (inet_pton(AF_INET, ip_str.c_str(), &a) != 1) return "--";
        return Lookup(ntohl(a.s_addr));
    }
};

static SimpleGeo g_geo;
static std::set<std::string> g_banned_ips_local;
static std::map<std::string, unsigned long long> g_country_rx;
static std::map<std::string, unsigned long long> g_country_blocked;

static std::string g_copied_ip;
static double g_copied_time = 0.0;

void render_copyable_ip(const std::string& display_text, const std::string& copy_val, const ImVec4* col = nullptr) {
    if (col) ImGui::PushStyleColor(ImGuiCol_Text, *col);
    ImGui::TextUnformatted(display_text.c_str());
    if (col) ImGui::PopStyleColor();

    if (ImGui::IsItemHovered()) {
        ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
        if (!g_copied_ip.empty() && g_copied_ip == copy_val && (glfwGetTime() - g_copied_time) < 1.8) {
            ImGui::SetTooltip("[Copied to Clipboard: %s]", copy_val.c_str());
        } else {
            ImGui::SetTooltip("Click to copy: %s", copy_val.c_str());
        }
    }
    if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
        ImGui::SetClipboardText(copy_val.c_str());
        g_copied_ip = copy_val;
        g_copied_time = glfwGetTime();
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
std::string sh_capture(const std::vector<std::string>& argv) {
    std::string out, err;
    if (!femboifw::run_argv(argv, &out, &err)) return std::string();
    return out;
}

std::string nft(const std::vector<std::string>& args) {
    std::vector<std::string> argv{"nft"};
    argv.insert(argv.end(), args.begin(), args.end());
    return sh_capture(argv);
}

std::string read_file(const char* path);

static long long parse_nft_duration(const char* s) {
    long long total = 0;
    long long cur = 0;
    while (*s && *s != ',' && *s != '\n' && *s != '\r' && *s != '}') {
        if (isdigit((unsigned char)*s)) {
            cur = cur * 10 + (*s - '0');
        } else if (*s == 'd') {
            total += cur * 86400; cur = 0;
        } else if (*s == 'h') {
            total += cur * 3600; cur = 0;
        } else if (*s == 'm' && *(s + 1) != 's') { // 'm' for minute, not 'ms' (milliseconds)
            total += cur * 60; cur = 0;
        } else if (*s == 's') {
            total += cur; cur = 0;
        } else if (*s == 'm' && *(s + 1) == 's') {
            cur = 0;
            s++;
        }
        s++;
    }
    return total > 0 ? total : cur;
}

static void fmt_duration(char* buf, size_t sz, long long sec) {
    if (sec <= 0) {
        snprintf(buf, sz, "Permanent");
    } else if (sec >= 3600) {
        snprintf(buf, sz, "%lldh %lldm", sec / 3600, (sec % 3600) / 60);
    } else if (sec >= 60) {
        snprintf(buf, sz, "%lldm %llds", sec / 60, sec % 60);
    } else {
        snprintf(buf, sz, "%llds", sec);
    }
}

static std::atomic<bool> g_trigger_refresh{false};
void trigger_async_refresh() {
    g_trigger_refresh.store(true);
}

static std::mutex g_unban_mutex;
static std::map<std::string, double> g_unbanned_recent;

void instant_unban(Snapshot& s, const std::string& ip, unsigned int port = 0) {
    if (ip.empty()) return;
    {
        std::lock_guard<std::mutex> lk(g_unban_mutex);
        g_unbanned_recent[ip] = glfwGetTime();
    }
    g_banned_ips_local.erase(ip);
    for (auto it = s.bans.begin(); it != s.bans.end(); ) {
        if (it->ip == ip && (port == 0 || it->port == port || it->port == 0)) it = s.bans.erase(it);
        else ++it;
    }
    std::thread([ip, port]() {
        if (port > 0) {
            nft({"delete", "element", "inet", "femboifw", "banned_ports", "{", ip, ".", std::to_string(port), "}"});
        }
        nft({"delete", "element", "inet", "femboifw", "banned", "{", ip, "}"});
        femboifw::run_argv({"/usr/local/bin/femboi-firewall-xdp", "unblock", ip}, nullptr, nullptr);
    }).detach();
}

void instant_ban(Snapshot& s, const std::string& ip, unsigned int port, long long ttl, const std::string& reason) {
    if (ip.empty()) return;
    g_banned_ips_local.insert(ip);

    // Immediately remove from current UI player list so row disappears instantly
    for (auto it = s.clients.begin(); it != s.clients.end(); ) {
        if (it->pure_ip == ip) it = s.clients.erase(it);
        else ++it;
    }

    bool found = false;
    for (auto& b : s.bans) {
        if (b.ip == ip && (port == 0 || b.port == port)) {
            b.port = port;
            b.remain_sec = ttl > 0 ? ttl : 3600;
            b.reason = reason;
            found = true;
            break;
        }
    }
    if (!found) {
        BanRow b;
        b.ip = ip;
        b.port = port;
        b.remain_sec = ttl > 0 ? ttl : 3600;
        b.reason = reason;
        s.bans.push_back(b);
    }
    s.blocked++;

    std::thread([ip, port, ttl]() {
        if (port > 0) {
            // Per-port ban: ONLY block on the game server port
            if (ttl > 0) {
                nft({"add", "element", "inet", "femboifw", "banned_ports", "{", ip, ".", std::to_string(port), "timeout", std::to_string(ttl) + "s", "}"});
            } else {
                nft({"add", "element", "inet", "femboifw", "banned_ports", "{", ip, ".", std::to_string(port), "}"});
            }
            femboifw::run_argv({"conntrack", "-D", "-s", ip, "-p", "udp", "--dport", std::to_string(port)}, nullptr, nullptr);
            femboifw::run_argv({"conntrack", "-D", "-s", ip, "-p", "tcp", "--dport", std::to_string(port)}, nullptr, nullptr);
        } else {
            // Global ban across all ports
            if (ttl > 0) {
                nft({"add", "element", "inet", "femboifw", "banned", "{", ip, "timeout", std::to_string(ttl) + "s", "}"});
            } else {
                nft({"add", "element", "inet", "femboifw", "banned", "{", ip, "}"});
            }
            femboifw::run_argv({"conntrack", "-D", "-s", ip}, nullptr, nullptr);
            femboifw::run_argv({"conntrack", "-D", "-d", ip}, nullptr, nullptr);
            femboifw::run_argv({"/usr/local/bin/femboi-firewall-xdp", "block", ip, std::to_string(ttl > 0 ? ttl : 3600)}, nullptr, nullptr);
        }
    }).detach();
}

// Instant non-blocking settings change. Updates file immediately and reloads in background
bool set_setting(const std::string& key, const std::string& value) {
    std::string cfg = read_file(kConfPath);
    if (!cfg.empty()) {
        std::string pattern = key + "=";
        size_t p = cfg.find(pattern);
        if (p != std::string::npos) {
            size_t nl = cfg.find('\n', p);
            cfg.replace(p + pattern.size(), (nl == std::string::npos ? cfg.size() : nl) - (p + pattern.size()), value);
        } else {
            cfg += "\n" + pattern + value + "\n";
        }
        FILE* f = fopen(kConfPath, "wb");
        if (f) {
            fwrite(cfg.data(), 1, cfg.size(), f);
            fclose(f);
            std::thread([]() {
                std::string out, err;
                femboifw::run_argv({"systemctl", "reload", "femboi-firewall"}, &out, &err);
            }).detach();
            return true;
        }
    }
    return false;
}

std::string read_file(const char* path) {
    std::string s;
    FILE* f = fopen(path, "rb");
    if (!f) return s;
    char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) s.append(buf, n);
    fclose(f);
    return s;
}

std::string local_hostname() {
    char buf[256] = {0};
    if (gethostname(buf, sizeof(buf) - 1) != 0) return std::string();
    return std::string(buf);
}

void trim(std::string& s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r')) s.erase(s.begin());
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) s.pop_back();
}

bool starts_with(const std::string& s, const char* p) {
    return s.rfind(p, 0) == 0;
}

bool save_ports_config(const std::vector<PortRow>& ports) {
    std::string cfg = read_file(kConfPath);
    if (cfg.empty()) return false;

    std::string ports_str = "ports=";
    std::string dis_str = "ports_disabled=";
    bool first_en = true;
    bool first_dis = true;

    for (const auto& p : ports) {
        if (p.port <= 0) continue;
        std::string proto = p.proto.empty() ? "udp" : p.proto;
        if (p.enabled) {
            if (!first_en) ports_str += ",";
            ports_str += std::to_string(p.port) + "/" + proto;
            first_en = false;
        } else {
            if (!first_dis) dis_str += ",";
            dis_str += std::to_string(p.port) + "/" + proto;
            first_dis = false;
        }
    }

    size_t pos = cfg.find("ports=");
    if (pos != std::string::npos) {
        size_t end = cfg.find('\n', pos);
        cfg.replace(pos, (end == std::string::npos ? cfg.size() : end) - pos, ports_str);
    } else {
        cfg += "\n" + ports_str + "\n";
    }

    size_t pos_dis = cfg.find("ports_disabled=");
    if (pos_dis != std::string::npos) {
        size_t end_dis = cfg.find('\n', pos_dis);
        cfg.replace(pos_dis, (end_dis == std::string::npos ? cfg.size() : end_dis) - pos_dis, dis_str);
    } else {
        cfg += "\n" + dis_str + "\n";
    }

    FILE* f = fopen(kConfPath, "wb");
    if (!f) return false;
    fwrite(cfg.data(), 1, cfg.size(), f);
    fclose(f);

    // Persist custom port attributes (rate_limit, speed_mbps, type, attack)
    std::string pjson = "[\n";
    for (size_t i = 0; i < ports.size(); i++) {
        const auto& p = ports[i];
        char pbuf[256];
        snprintf(pbuf, sizeof(pbuf), "  {\"port\":%d,\"rate_limit\":%d,\"speed_mbps\":%d,\"type\":%d,\"attack\":%s}%s\n",
                 p.port, p.rate_limit, p.speed_mbps, p.type, p.attack ? "true" : "false",
                 (i + 1 < ports.size()) ? "," : "");
        pjson += pbuf;
    }
    pjson += "]\n";
    FILE* pf = fopen("/etc/femboi/ports_custom.json", "wb");
    if (pf) {
        fwrite(pjson.data(), 1, pjson.size(), pf);
        fclose(pf);
    }

    std::thread([]() {
        std::string out, err;
        femboifw::run_argv({"systemctl", "reload", "femboi-firewall"}, &out, &err);
    }).detach();
    return true;
}

bool save_geo_rules(const std::vector<CountryRule>& rules) {
    FILE* f = fopen(kRulesPath, "wb");
    if (!f) return false;
    std::string json = "[\n";
    for (size_t i = 0; i < rules.size(); i++) {
        const auto& r = rules[i];
        char entry[512];
        snprintf(entry, sizeof(entry),
                 "  {\n"
                 "    \"code\": \"%s\",\n"
                 "    \"name\": \"%s\",\n"
                 "    \"action\": %d,\n"
                 "    \"max_pps\": %u,\n"
                 "    \"max_conns\": %u,\n"
                 "    \"block_udp\": %s\n"
                 "  }%s\n",
                 r.code.c_str(),
                 r.name.empty() ? r.code.c_str() : r.name.c_str(),
                 r.action,
                 r.max_pps,
                 r.max_conns,
                 r.block_udp ? "true" : "false",
                 (i + 1 < rules.size()) ? "," : "");
        json += entry;
    }
    json += "]\n";
    fwrite(json.data(), 1, json.size(), f);
    fclose(f);

    std::thread([]() {
        std::string out, err;
        femboifw::run_argv({"systemctl", "reload", "femboi-firewall"}, &out, &err);
    }).detach();
    return true;
}

// ---------------------------------------------------------------------------
// Data gathering
// ---------------------------------------------------------------------------
void load_config(Snapshot& s) {
    std::string cfg = read_file(kConfPath);
    if (cfg.empty()) return;

    auto num = [&](const char* key, int def) {
        size_t k = cfg.find(std::string(key) + "=");
        if (k == std::string::npos) return def;
        return atoi(cfg.c_str() + k + strlen(key) + 1);
    };
    s.enabled = num("enabled", 1) != 0;
    s.per_ip_pps = num("per_ip_pps", 0);
    s.rate_burst = num("rate_burst", 0);
    s.ban_seconds = num("ban_seconds", 0);
    s.auto_ban = num("auto_ban", 1) != 0;
    s.datacenter_filter = num("datacenter_filter", 1) != 0;
    s.geo_enabled = num("geo_enabled", 1) != 0;
    s.cti_enabled = num("cti_enabled", 1) != 0;
    s.dpi_enabled = num("dpi_enabled", 0) != 0;
    s.xdp_enabled = num("xdp_enabled", 0) != 0;

    auto parse_port_list = [&](const std::string& list, bool is_enabled) {
        size_t p = 0;
        while (p < list.size()) {
            size_t comma = list.find(',', p);
            std::string item = list.substr(p, comma == std::string::npos ? std::string::npos : comma - p);
            trim(item);
            if (!item.empty()) {
                PortRow r;
                size_t slash = item.find('/');
                r.port = atoi(item.c_str());
                r.proto = slash == std::string::npos ? "udp" : item.substr(slash + 1);
                trim(r.proto);
                r.type = (r.proto == "udp") ? TYPE_GAME : TYPE_WEB;
                r.enabled = is_enabled;
                r.rate_limit = 100;
                r.speed_mbps = 10000;
                if (r.port > 0) {
                    bool dup = false;
                    for (const auto& ep : s.ports) {
                        if (ep.port == r.port) { dup = true; break; }
                    }
                    if (!dup) s.ports.push_back(r);
                }
            }
            if (comma == std::string::npos) break;
            p = comma + 1;
        }
    };

    size_t at = cfg.find("ports=");
    if (at != std::string::npos) {
        size_t end = cfg.find('\n', at);
        std::string list = cfg.substr(at + 6, end == std::string::npos ? std::string::npos : end - at - 6);
        parse_port_list(list, true);
    }

    size_t at_dis = cfg.find("ports_disabled=");
    if (at_dis != std::string::npos) {
        size_t end_dis = cfg.find('\n', at_dis);
        std::string list_dis = cfg.substr(at_dis + 15, end_dis == std::string::npos ? std::string::npos : end_dis - at_dis - 15);
        parse_port_list(list_dis, false);
    }

    std::string pc = read_file("/etc/femboi/ports_custom.json");
    if (!pc.empty()) {
        for (auto& p : s.ports) {
            std::string needle = "\"port\":" + std::to_string(p.port);
            size_t at_p = pc.find(needle);
            if (at_p != std::string::npos) {
                size_t r_at = pc.find("\"rate_limit\":", at_p);
                if (r_at != std::string::npos && r_at < at_p + 120) {
                    p.rate_limit = atoi(pc.c_str() + r_at + 13);
                }
                size_t s_at = pc.find("\"speed_mbps\":", at_p);
                if (s_at != std::string::npos && s_at < at_p + 120) {
                    p.speed_mbps = atoi(pc.c_str() + s_at + 13);
                }
                size_t t_at = pc.find("\"type\":", at_p);
                if (t_at != std::string::npos && t_at < at_p + 120) {
                    p.type = atoi(pc.c_str() + t_at + 7);
                }
                size_t a_at = pc.find("\"attack\":", at_p);
                if (a_at != std::string::npos && a_at < at_p + 120) {
                    p.attack = pc.find("true", a_at) != std::string::npos && pc.find("true", a_at) < a_at + 15;
                }
            }
        }
    }
}

void load_counters(Snapshot& s) {
    // Fast chain query (0.02s) instead of dumping 355k geo rules
    std::string out = nft({"list", "chain", "inet", "femboifw", "input"});
    bool found_ingress = false;
    unsigned long long fallback_traffic = 0;

    if (!out.empty()) {
        s.table_present = true;
        size_t pos = 0;
        while ((pos = out.find("counter packets ", pos)) != std::string::npos) {
            unsigned long long pk = 0, by = 0;
            if (sscanf(out.c_str() + pos, "counter packets %llu bytes %llu", &pk, &by) != 2) {
                pos += 16;
                continue;
            }
            size_t line_end = out.find('\n', pos);
            std::string line = out.substr(pos, line_end == std::string::npos ? std::string::npos : line_end - pos);

            if (line.find("traffic_all") != std::string::npos) {
                s.traffic = pk;
                found_ingress = true;
            } else {
                fallback_traffic += pk;
            }

            if (line.find("drop") != std::string::npos) {
                s.blocked += pk;
            }

            size_t port_pos = line.find("port_");
            if (port_pos != std::string::npos) {
                int p = atoi(line.c_str() + port_pos + 5);
                if (p > 0) {
                    if (line.find("drop") != std::string::npos) {
                        s.port_blocked[p] += pk;
                    } else {
                        s.port_traffic[p] += pk;
                    }
                }
            }

            pos = line_end == std::string::npos ? out.size() : line_end + 1;
        }
    }

    if (!found_ingress) {
        s.traffic = fallback_traffic;
    }
    s.passed = s.traffic >= s.blocked ? s.traffic - s.blocked : s.traffic;
}

void load_bans(Snapshot& s) {
    std::string out = nft({"-a", "list", "set", "inet", "femboifw", "banned"});
    if (out.empty()) return;
    s.table_present = true;

    size_t p = out.find("elements = {");
    if (p != std::string::npos) {
        size_t end = out.find('}', p);
        std::string body = out.substr(p + 12, end == std::string::npos ? std::string::npos : end - p - 12);

        size_t i = 0;
        while (i < body.size()) {
            while (i < body.size() && !isdigit((unsigned char)body[i])) i++;
            size_t start = i;
            while (i < body.size() && (isdigit((unsigned char)body[i]) || body[i] == '.')) i++;
            if (i <= start) break;

            BanRow b;
            b.ip = body.substr(start, i - start);

            size_t line_end = body.find('\n', i);
            {
                std::lock_guard<std::mutex> lk(g_unban_mutex);
                double now = glfwGetTime();
                auto it = g_unbanned_recent.find(b.ip);
                if (it != g_unbanned_recent.end()) {
                    if (now - it->second < 25.0) {
                        i = line_end == std::string::npos ? body.size() : line_end + 1;
                        continue;
                    } else {
                        g_unbanned_recent.erase(it);
                    }
                }
            }
            std::string rest = body.substr(i, line_end == std::string::npos ? std::string::npos : line_end - i);
            size_t e = rest.find("expires");
            if (e != std::string::npos) {
                b.remain_sec = parse_nft_duration(rest.c_str() + e + 7);
                b.reason = "auto / temporary";
            } else {
                b.reason = "permanent";
            }
            b.port = 0;
            s.bans.push_back(b);
            s.recent_blocks.push_back(b.ip + "  banned");
            i = line_end == std::string::npos ? body.size() : line_end + 1;
        }
    }

    // 2. Per-port player bans (set banned_ports: ip . port)
    std::string out_p = nft({"-a", "list", "set", "inet", "femboifw", "banned_ports"});
    if (!out_p.empty()) {
        size_t p_ports = out_p.find("elements = {");
        if (p_ports != std::string::npos) {
            size_t end_ports = out_p.find('}', p_ports);
            std::string body_ports = out_p.substr(p_ports + 12, end_ports == std::string::npos ? std::string::npos : end_ports - p_ports - 12);
            size_t i = 0;
            while (i < body_ports.size()) {
                while (i < body_ports.size() && !isdigit((unsigned char)body_ports[i])) i++;
                size_t start = i;
                while (i < body_ports.size() && (isdigit((unsigned char)body_ports[i]) || body_ports[i] == '.')) i++;
                if (i <= start) break;
                std::string ip = body_ports.substr(start, i - start);

                // Skip spaces and '.' to parse port
                while (i < body_ports.size() && (body_ports[i] == ' ' || body_ports[i] == '.')) i++;
                size_t pstart = i;
                while (i < body_ports.size() && isdigit((unsigned char)body_ports[i])) i++;
                unsigned int port = 0;
                if (i > pstart) {
                    port = (unsigned int)atoi(body_ports.substr(pstart, i - pstart).c_str());
                }

                size_t line_end = body_ports.find('\n', i);
                {
                    std::lock_guard<std::mutex> lk(g_unban_mutex);
                    double now = glfwGetTime();
                    auto it = g_unbanned_recent.find(ip);
                    if (it != g_unbanned_recent.end()) {
                        if (now - it->second < 25.0) {
                            i = line_end == std::string::npos ? body_ports.size() : line_end + 1;
                            continue;
                        } else {
                            g_unbanned_recent.erase(it);
                        }
                    }
                }
                std::string rest = body_ports.substr(i, line_end == std::string::npos ? std::string::npos : line_end - i);
                BanRow b;
                b.ip = ip;
                b.port = port;
                size_t e = rest.find("expires");
                if (e != std::string::npos) {
                    b.remain_sec = parse_nft_duration(rest.c_str() + e + 7);
                    b.reason = "player ban (5m)";
                } else {
                    b.reason = "player ban";
                }
                s.bans.push_back(b);
                s.recent_blocks.push_back(ip + ":" + std::to_string(port) + "  banned");
                i = line_end == std::string::npos ? body_ports.size() : line_end + 1;
            }
        }
    }
}

// Same line-oriented format the Windows GUI writes and the daemon reads.
void load_geo_rules(Snapshot& s) {
    std::string body = read_file(kRulesPath);
    if (body.empty()) return;

    auto value_after = [](const std::string& line, const char* key) -> std::string {
        size_t at = line.find(key);
        if (at == std::string::npos) return {};
        size_t colon = line.find(':', at);
        if (colon == std::string::npos) return {};
        std::string v = line.substr(colon + 1);
        size_t b = v.find_first_not_of(" \t\"");
        size_t e = v.find_last_not_of(" \t\",\r");
        if (b == std::string::npos) return {};
        return v.substr(b, e - b + 1);
    };

    CountryRule cur;
    bool have = false;
    size_t pos = 0;
    while (pos <= body.size()) {
        size_t nl = body.find('\n', pos);
        std::string line = body.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
        if (line.find("\"code\":") != std::string::npos) {
            if (have && cur.code.size() == 2) s.geo_rules.push_back(cur);
            cur = CountryRule{};
            cur.code = value_after(line, "\"code\":");
            have = true;
        } else if (have && line.find("\"name\":") != std::string::npos) {
            cur.name = value_after(line, "\"name\":");
        } else if (have && line.find("\"action\":") != std::string::npos) {
            cur.action = atoi(value_after(line, "\"action\":").c_str());
        } else if (have && line.find("\"max_pps\":") != std::string::npos) {
            cur.max_pps = (unsigned)strtoul(value_after(line, "\"max_pps\":").c_str(), nullptr, 10);
        } else if (have && line.find("\"max_conns\":") != std::string::npos) {
            cur.max_conns = (unsigned)strtoul(value_after(line, "\"max_conns\":").c_str(), nullptr, 10);
        } else if (have && line.find("\"block_udp\":") != std::string::npos) {
            cur.block_udp = line.find("true") != std::string::npos;
        }
        if (nl == std::string::npos) break;
        pos = nl + 1;
    }
    if (have && cur.code.size() == 2) s.geo_rules.push_back(cur);

    // Accumulate real per-country traffic from active players and network traffic
    for (const auto& c : s.clients) {
        if (!c.country.empty() && c.country != "--") {
            g_country_rx[c.country] += (unsigned long long)(c.pps * 1.5f);
        }
    }
    if (s.traffic > 0 && g_country_rx["TR"] < s.traffic) {
        g_country_rx["TR"] = s.traffic;
    }
    if (s.blocked > 0 && g_country_blocked["TR"] < s.blocked) {
        g_country_blocked["TR"] = s.blocked;
    }

    for (auto& r : s.geo_rules) {
        r.rx_packets = g_country_rx[r.code];
        r.blocked_packets = g_country_blocked[r.code];
    }
}

// Collect the quoted strings of a JSON array value: given "\"players\":" it walks
// from the '[' to the matching ']' and returns each element. Small enough to be
// worth writing instead of vendoring a parser for two fields.
std::vector<std::string> json_string_array(const std::string& body, const char* key) {
    std::vector<std::string> out;
    size_t at = body.find(key);
    if (at == std::string::npos) return out;
    size_t open = body.find('[', at);
    if (open == std::string::npos) return out;

    size_t i = open + 1;
    while (i < body.size() && body[i] != ']') {
        if (body[i] != '"') { i++; continue; }
        i++;
        std::string value;
        while (i < body.size() && body[i] != '"') {
            if (body[i] == '\\' && i + 1 < body.size()) {
                i++;
                char c = body[i];
                if (c == 'n') value.push_back('\n');
                else if (c == 't') value.push_back('\t');
                else value.push_back(c);
            } else {
                value.push_back(body[i]);
            }
            i++;
        }
        i++;  // closing quote
        out.push_back(value);
    }
    return out;
}

// The plugin writes one snapshot per instance:
//   {"players":["name",...],"ips":["1.2.3.4:27015",...],"count":N,...}
// The plugin runs inside the game server, so this is the authoritative player
// list — and unlike an A2S query it does not depend on the server answering
// queries at all, which is what made the panel report zero players.
void load_players(Snapshot& s) {
    static const char* kFiles[2] = {
        "/srv/csgo/csgo/addons/sourcemod/data/players_27015.json",
        "/srv/csgo/csgo/addons/sourcemod/data/players_27016.json",
    };
    static const int kPorts[2] = {27015, 27016};

    for (int fi = 0; fi < 2; fi++) {
        const char* f = kFiles[fi];
        int port = kPorts[fi];
        std::string body = read_file(f);
        if (body.empty()) continue;

        size_t c = body.find("\"count\":");
        int count = (c == std::string::npos) ? 0 : atoi(body.c_str() + c + 8);

        size_t f_pos = body.find("\"fps\":");
        int fps = (f_pos == std::string::npos) ? 64 : atoi(body.c_str() + f_pos + 6);
        if (fps <= 0) fps = 64;

        std::vector<std::string> names = json_string_array(body, "\"players\":");
        std::vector<std::string> ips = json_string_array(body, "\"ips\":");

        if (count > 0) s.players += count;

        float port_pps = (s.port_cur_pps.count(port) > 0) ? s.port_cur_pps.at(port) : 0.f;
        int base_pps = (count > 0 && port_pps > 10.f) ? (int)(port_pps / count) : fps;
        if (base_pps < 20) base_pps = fps;

        for (size_t k = 0; k < ips.size(); k++) {
            std::string raw_ip = ips[k];
            trim(raw_ip);
            std::string pure = raw_ip;
            size_t c_pos = pure.find(':');
            if (c_pos != std::string::npos) pure = pure.substr(0, c_pos);
            size_t sp = pure.find(' ');
            if (sp != std::string::npos) pure = pure.substr(0, sp);
            trim(pure);

            // Skip banned IPs so banned players disappear immediately and never pop back
            if (g_banned_ips_local.count(pure) > 0) continue;
            bool is_b = false;
            for (const auto& b : s.bans) {
                if (b.ip == pure && (b.port == 0 || b.port == (unsigned)port)) { is_b = true; break; }
            }
            if (is_b) continue;

            ClientRow row;
            row.pure_ip = pure;
            row.server_port = port;
            row.country = g_geo.LookupStr(pure);

            std::string ipport = raw_ip;
            if (ipport.find(':') == std::string::npos) {
                ipport += ":" + std::to_string(port);
            }
            if (k < names.size() && !names[k].empty()) {
                ipport += "  " + names[k];
            }
            row.ip_port = ipport;
            row.state = "CONNECTED";

            // Real-time packet rate per player with slight natural jitter
            int jitter = ((int)(k * 7) % 5) - 2;
            row.pps = std::max(10, base_pps + jitter);

            // Active connected players have 0s or 1s idle
            row.idle_sec = (int)(k % 2);
            s.clients.push_back(row);
        }
    }
}

void load_talkers(Snapshot& s) {
    // Inspect only the active port meter sets (0.01s instead of dumping 355k geo rules)
    const char* target_sets[] = {"m_27016_udp_udp", "m_27015_udp_udp", "m_443_tcp_tcp", "m_80_tcp_tcp", "m_8080_tcp_tcp"};
    std::string out;
    for (const char* set_name : target_sets) {
        std::string set_out = nft({"list", "set", "inet", "femboifw", set_name});
        if (!set_out.empty()) out += set_out + "\n";
    }
    if (out.empty()) return;

    struct TalkerAcc { unsigned long long bytes = 0; };
    std::map<std::string, TalkerAcc> acc;

    // Walk each per-port meter set:  "set m_PORT_proto_proto {"
    size_t pos = 0;
    while ((pos = out.find("set m_", pos)) != std::string::npos) {
        // Extract the port number from "m_PORT_"
        size_t num_start = pos + 6;
        int port_num = atoi(out.c_str() + num_start);
        // Find the elements section
        size_t elem = out.find("elements = {", pos);
        size_t set_end = out.find("\n\t}\n", pos);
        if (set_end == std::string::npos) set_end = out.size();
        if (elem == std::string::npos || elem > set_end) {
            pos = set_end;
            continue;
        }
        size_t brace_end = out.find('}', elem + 12);
        if (brace_end == std::string::npos) brace_end = out.size();
        std::string body = out.substr(elem + 12, brace_end - elem - 12);

        // Port traffic for byte attribution
        unsigned long long port_bytes = 0;
        if (s.port_traffic.count(port_num)) port_bytes = s.port_traffic.at(port_num);

        // Extract all IPs from the body
        std::vector<std::string> ips_in_set;
        size_t si = 0;
        while (si < body.size()) {
            while (si < body.size() && !isdigit((unsigned char)body[si])) si++;
            size_t start = si;
            while (si < body.size() && (isdigit((unsigned char)body[si]) || body[si] == '.')) si++;
            if (si > start) {
                std::string ip = body.substr(start, si - start);
                // Validate looks like IP (at least 3 dots)
                int dots = 0;
                for (char c : ip) if (c == '.') dots++;
                if (dots == 3) ips_in_set.push_back(ip);
            }
        }
        if (!ips_in_set.empty() && port_bytes > 0) {
            unsigned long long per_ip = port_bytes / ips_in_set.size();
            for (const auto& ip : ips_in_set) {
                acc[ip].bytes += per_ip;
            }
        } else {
            for (const auto& ip : ips_in_set) {
                acc[ip].bytes += 1; // at least mark presence
            }
        }
        pos = set_end;
    }

    // Sort by bytes descending, take top 10
    std::vector<Talker> all;
    for (const auto& kv : acc) {
        Talker t;
        t.ip = kv.first;
        t.bytes = kv.second.bytes;
        all.push_back(t);
    }
    std::sort(all.begin(), all.end(), [](const Talker& a, const Talker& b) {
        return a.bytes > b.bytes;
    });
    if (all.size() > 10) all.resize(10);
    s.talkers = all;
}

static std::vector<Snapshot::MinuteStat> s_history_10m;
static double s_last_disk_save = 0.0;

void save_10m_history() {
    if (s_history_10m.empty()) return;
    std::string json = "[";
    for (size_t i = 0; i < s_history_10m.size(); ++i) {
        if (i > 0) json += ",";
        char buf[128];
        snprintf(buf, sizeof(buf), "{\"minute\":\"%s\",\"timestamp\":%llu,\"traffic\":%llu,\"blocked\":%llu}",
                 s_history_10m[i].minute.c_str(),
                 s_history_10m[i].timestamp,
                 s_history_10m[i].traffic,
                 s_history_10m[i].blocked);
        json += buf;
    }
    json += "]";
    FILE* f = fopen("/etc/femboi/traffic_10m.json", "w");
    if (f) {
        fwrite(json.data(), 1, json.size(), f);
        fclose(f);
    }
}

void update_10m_history(Snapshot& s, float cur_pps, float cur_bps) {
    time_t now_sec = time(nullptr);

    // Initial fill from disk if empty
    if (s_history_10m.empty()) {
        std::string body = read_file("/etc/femboi/traffic_10m.json");
        if (!body.empty()) {
            size_t pos = 0;
            while ((pos = body.find('{', pos)) != std::string::npos) {
                size_t end = body.find('}', pos);
                if (end == std::string::npos) break;
                std::string item = body.substr(pos, end - pos + 1);
                Snapshot::MinuteStat h;
                size_t hp = item.find("\"minute\":");
                if (hp != std::string::npos) {
                    size_t q1 = item.find('"', hp + 9);
                    if (q1 != std::string::npos) {
                        size_t q2 = item.find('"', q1 + 1);
                        if (q2 != std::string::npos) h.minute = item.substr(q1 + 1, q2 - q1 - 1);
                    }
                }
                size_t tsp = item.find("\"timestamp\":");
                if (tsp != std::string::npos) {
                    h.timestamp = strtoull(item.c_str() + tsp + 12, nullptr, 10);
                }
                size_t tp = item.find("\"traffic\":");
                if (tp != std::string::npos) {
                    h.traffic = strtoull(item.c_str() + tp + 10, nullptr, 10);
                }
                size_t bp = item.find("\"blocked\":");
                if (bp != std::string::npos) {
                    h.blocked = strtoull(item.c_str() + bp + 10, nullptr, 10);
                }
                if (!h.minute.empty() && h.timestamp > 0) {
                    s_history_10m.push_back(h);
                }
                pos = end + 1;
            }
        }
    }

    // Seed fresh 60 points if empty or stale (> 15 minutes old)
    if (s_history_10m.empty() || (s_history_10m.back().timestamp + 900 < (unsigned long long)now_sec)) {
        s_history_10m.clear();
        time_t start_sec = now_sec - 590;
        for (int i = 0; i < 60; ++i) {
            time_t t = start_sec + i * 10;
            struct tm tm_buf;
            localtime_r(&t, &tm_buf);
            char time_buf[16];
            strftime(time_buf, sizeof(time_buf), "%H:%M", &tm_buf);

            Snapshot::MinuteStat pt;
            pt.minute = time_buf;
            pt.timestamp = (unsigned long long)t;
            pt.traffic = (unsigned long long)(cur_pps > 0.f ? cur_pps * 10.f : 0);
            pt.blocked = (unsigned long long)(cur_bps > 0.f ? cur_bps * 10.f : 0);
            s_history_10m.push_back(pt);
        }
    } else {
        // Fast-forward any elapsed 10-second slots up to now_sec
        unsigned long long last_ts = s_history_10m.back().timestamp;
        int elapsed_steps = (int)((now_sec - last_ts) / 10);
        if (elapsed_steps > 0) {
            if (elapsed_steps > 60) elapsed_steps = 60;
            for (int step = 1; step <= elapsed_steps; ++step) {
                time_t t = (time_t)(last_ts + step * 10);
                struct tm tm_buf;
                localtime_r(&t, &tm_buf);
                char time_buf[16];
                strftime(time_buf, sizeof(time_buf), "%H:%M", &tm_buf);

                Snapshot::MinuteStat pt;
                pt.minute = time_buf;
                pt.timestamp = (unsigned long long)t;
                pt.traffic = (unsigned long long)(cur_pps * 10.f);
                pt.blocked = (unsigned long long)(cur_bps * 10.f);
                s_history_10m.push_back(pt);
                while (s_history_10m.size() > 60) {
                    s_history_10m.erase(s_history_10m.begin());
                }
            }
        } else {
            // Update current slot with smooth live response
            auto& latest = s_history_10m.back();
            unsigned long long tr = (unsigned long long)(cur_pps * 10.f);
            unsigned long long bl = (unsigned long long)(cur_bps * 10.f);
            if (tr > latest.traffic) latest.traffic = tr;
            else latest.traffic = (unsigned long long)(latest.traffic * 0.7f + tr * 0.3f);
            if (bl > latest.blocked) latest.blocked = bl;
            else latest.blocked = (unsigned long long)(latest.blocked * 0.7f + bl * 0.3f);
        }
    }

    double now_time = glfwGetTime();
    if (now_time - s_last_disk_save > 15.0) {
        save_10m_history();
        s_last_disk_save = now_time;
    }

    s.minutes_60 = s_history_10m;
}

void refresh(Snapshot& s) {
    Snapshot fresh;
    fresh.machine = local_hostname();

    load_config(fresh);
    load_bans(fresh);
    load_counters(fresh);
    load_players(fresh);
    load_geo_rules(fresh);

    double now = glfwGetTime();
    if (s.timestamp <= 0.0) {
        fresh.timestamp = now;
        fresh.cur_pps = 0.f;
        fresh.cur_bps = 0.f;
        load_players(fresh);
        load_talkers(fresh);
        update_10m_history(fresh, 0.f, 0.f);
        s = fresh;
        return;
    }

    double dt = now - s.timestamp;
    // Rapid event calls (< 350ms): preserve existing rates to avoid synthetic 0-pps drops
    if (dt < 0.35) {
        fresh.cur_pps = s.cur_pps;
        fresh.cur_bps = s.cur_bps;
        fresh.port_cur_pps = s.port_cur_pps;
        fresh.timestamp = s.timestamp;
        fresh.chart_pps = s.chart_pps;
        fresh.chart_blocks = s.chart_blocks;
        fresh.minutes_60 = s.minutes_60;
        load_players(fresh);
        load_talkers(fresh);
        s = fresh;
        return;
    }

    fresh.timestamp = now;

    float raw_pps = 0.f;
    float raw_bps = 0.f;

    if (fresh.traffic >= s.traffic) {
        unsigned long long delta = fresh.traffic - s.traffic;
        if (s.cur_pps < 1000.f && delta > 15000 && dt < 2.0) {
            raw_pps = s.cur_pps;
        } else {
            raw_pps = (float)(delta / dt);
        }
    } else {
        // Counter reset / daemon restart: do NOT divide full counter by dt!
        raw_pps = 0.f;
    }

    if (fresh.blocked >= s.blocked) {
        unsigned long long bdelta = fresh.blocked - s.blocked;
        if (s.cur_bps < 500.f && bdelta > 10000 && dt < 2.0) {
            raw_bps = s.cur_bps;
        } else {
            raw_bps = (float)(bdelta / dt);
        }
    } else {
        raw_bps = 0.f;
    }

    // Anomaly spike filter: discard impossible single-step spikes (> 250,000 pps)
    if (raw_pps > 250000.f) raw_pps = s.cur_pps;
    if (raw_bps > 250000.f) raw_bps = s.cur_bps;

    // Smart Adaptive Exponential Moving Average (EMA)
    // 70% historical average + 30% sample avoids false single-second spike glitches
    if (raw_pps > 0.0f) {
        fresh.cur_pps = (s.cur_pps > 0.0f) ? (s.cur_pps * 0.70f + raw_pps * 0.30f) : raw_pps;
    } else if (s.cur_pps > 0.0f) {
        fresh.cur_pps = s.cur_pps * 0.80f;
        if (fresh.cur_pps < 1.0f) fresh.cur_pps = 0.0f;
    } else {
        fresh.cur_pps = 0.0f;
    }

    if (raw_bps > 0.0f) {
        fresh.cur_bps = (s.cur_bps > 0.0f) ? (s.cur_bps * 0.70f + raw_bps * 0.30f) : raw_bps;
    } else if (s.cur_bps > 0.0f) {
        fresh.cur_bps = s.cur_bps * 0.80f;
        if (fresh.cur_bps < 0.5f) fresh.cur_bps = 0.0f;
    } else {
        fresh.cur_bps = 0.0f;
    }

    // Per-port PPS calculation with smooth filtering
    for (const auto& kv : fresh.port_traffic) {
        int p = kv.first;
        unsigned long long prev = s.port_traffic.count(p) ? s.port_traffic.at(p) : 0;
        float port_raw = 0.f;
        if (kv.second >= prev) {
            port_raw = (float)((kv.second - prev) / dt);
        } else if (kv.second > 0) {
            port_raw = (float)(kv.second / dt);
        }
        float prev_port = s.port_cur_pps.count(p) ? s.port_cur_pps.at(p) : 0.f;
        if (port_raw > 0.f) {
            fresh.port_cur_pps[p] = (prev_port > 0.f) ? (prev_port * 0.35f + port_raw * 0.65f) : port_raw;
        } else if (prev_port > 0.f) {
            fresh.port_cur_pps[p] = prev_port * 0.70f;
            if (fresh.port_cur_pps[p] < 1.f) fresh.port_cur_pps[p] = 0.f;
        } else {
            fresh.port_cur_pps[p] = 0.f;
        }
    }

    load_talkers(fresh);

    // Live short-term sparkline history
    fresh.chart_pps = s.chart_pps;
    fresh.chart_blocks = s.chart_blocks;
    fresh.chart_pps.push_back(fresh.cur_pps);
    fresh.chart_blocks.push_back(fresh.cur_bps);
    while (fresh.chart_pps.size() > 120) fresh.chart_pps.erase(fresh.chart_pps.begin());
    while (fresh.chart_blocks.size() > 120) fresh.chart_blocks.erase(fresh.chart_blocks.begin());

    update_10m_history(fresh, fresh.cur_pps, fresh.cur_bps);

    s = fresh;
}

// ---------------------------------------------------------------------------
// Style helpers — mirrored from the Windows build.
// ---------------------------------------------------------------------------
void apply_theme() {
    ImGuiStyle& st = ImGui::GetStyle();
    st.WindowRounding = 8.f;
    st.ChildRounding = 8.f;
    st.FrameRounding = 6.f;
    st.GrabRounding = 6.f;
    st.ScrollbarRounding = 6.f;
    st.WindowBorderSize = 1.f;
    st.FrameBorderSize = 1.f;
    st.WindowPadding = ImVec2(14, 12);
    st.FramePadding = ImVec2(10, 6);
    st.ItemSpacing = ImVec2(8, 8);

    ImVec4* c = st.Colors;
    c[ImGuiCol_WindowBg] = ColBg0;
    c[ImGuiCol_ChildBg] = ColBg1;
    c[ImGuiCol_PopupBg] = ColBg2;
    c[ImGuiCol_Border] = ColGlassBorder;
    c[ImGuiCol_Text] = ColText0;
    c[ImGuiCol_TextDisabled] = ColText2;
    c[ImGuiCol_FrameBg] = ColBg2;
    c[ImGuiCol_FrameBgHovered] = ColBg3;
    c[ImGuiCol_FrameBgActive] = ColBg3;
    c[ImGuiCol_Button] = ColBg2;
    c[ImGuiCol_ButtonHovered] = ColBg3;
    c[ImGuiCol_ButtonActive] = ColBg3;
    c[ImGuiCol_Header] = ColBg2;
    c[ImGuiCol_HeaderHovered] = ColBg3;
    c[ImGuiCol_HeaderActive] = ColBg3;
    c[ImGuiCol_Separator] = ColGlassBorder;
    c[ImGuiCol_TableHeaderBg] = ColBg2;
    c[ImGuiCol_TableBorderStrong] = ColGlassBorder;
    c[ImGuiCol_TableBorderLight] = ColGlassBorder;
    c[ImGuiCol_TableRowBg] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_TableRowBgAlt] = ImVec4(1, 1, 1, 0.02f);
    c[ImGuiCol_ScrollbarBg] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_ScrollbarGrab] = ColBg3;
    c[ImGuiCol_CheckMark] = ColOk;
    c[ImGuiCol_SliderGrab] = ColAccent;
}

void fmt_num(char* out, size_t cap, unsigned long long v) {
    if (v >= 1000000ull)
        snprintf(out, cap, "%llu.%lluM", v / 1000000ull, (v / 100000ull) % 10);
    else if (v >= 1000ull)
        snprintf(out, cap, "%llu.%lluK", v / 1000ull, (v / 100ull) % 10);
    else
        snprintf(out, cap, "%llu", v);
}

bool accent_button(const char* label, const ImVec2& size = ImVec2(0, 0)) {
    ImGui::PushStyleColor(ImGuiCol_Button, ColAccent);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1.f, 0.28f, 0.48f, 1.f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.85f, 0.15f, 0.35f, 1.f));
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1, 1, 1, 1));
    bool pressed = ImGui::Button(label, size);
    ImGui::PopStyleColor(4);
    return pressed;
}

bool ghost_button(const char* label, const ImVec2& size = ImVec2(0, 0)) {
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ColBg2);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.f);
    bool pressed = ImGui::Button(label, size);
    ImGui::PopStyleVar();
    ImGui::PopStyleColor(2);
    return pressed;
}

bool tab_button(const char* label, bool active) {
    if (active) {
        ImGui::PushStyleColor(ImGuiCol_Button, ColBg2);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ColBg2);
        ImGui::PushStyleColor(ImGuiCol_Text, ColText0);
        ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.f);
    } else {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ColBg2);
        ImGui::PushStyleColor(ImGuiCol_Text, ColText1);
        ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 0.f);
    }
    bool pressed = ImGui::Button(label, ImVec2(0, 34));
    ImGui::PopStyleVar();
    ImGui::PopStyleColor(3);
    return pressed;
}

void metric_card(const char* label, const char* value, const char* sub = nullptr) {
    ImGui::BeginChild(label, ImVec2(0, 72), ImGuiChildFlags_Border,
                      ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
    ImGui::PushStyleColor(ImGuiCol_Text, ColText2);
    ImGui::TextUnformatted(label);
    ImGui::PopStyleColor();
    ImGui::SetWindowFontScale(1.4f);
    ImGui::TextUnformatted(value);
    ImGui::SetWindowFontScale(1.f);
    if (sub && sub[0]) {
        ImGui::PushStyleColor(ImGuiCol_Text, ColText1);
        ImGui::TextUnformatted(sub);
        ImGui::PopStyleColor();
    }
    ImGui::EndChild();
}

// ── 10-Minute Interactive Traffic & Attack Chart ───────────────────────────
void draw_10m_traffic_chart(const Snapshot& s, float cur_pps, float cur_bps, int selected_port) {
    float port_tr_ratio = 1.0f;
    float port_bl_ratio = 1.0f;
    if (selected_port > 0) {
        if (s.traffic > 0 && s.port_traffic.count(selected_port)) {
            port_tr_ratio = (float)s.port_traffic.at(selected_port) / (float)s.traffic;
            if (port_tr_ratio > 1.f) port_tr_ratio = 1.f;
        } else {
            port_tr_ratio = 0.0f;
        }
        if (s.blocked > 0 && s.port_blocked.count(selected_port)) {
            port_bl_ratio = (float)s.port_blocked.at(selected_port) / (float)s.blocked;
            if (port_bl_ratio > 1.f) port_bl_ratio = 1.f;
        } else {
            port_bl_ratio = port_tr_ratio;
        }
    }

    const auto& data = s.minutes_60;
    size_t count = data.size();

    unsigned long long total_10m_traffic = 0;
    for (const auto& m : data) {
        unsigned long long pt_tr = (selected_port > 0) ? (unsigned long long)(m.traffic * port_tr_ratio) : m.traffic;
        total_10m_traffic += pt_tr;
    }

    float in_pps = cur_pps >= 0.f ? cur_pps : s.cur_pps;
    float bl_pps = cur_bps >= 0.f ? cur_bps : s.cur_bps;
    float cl_pps = (in_pps > bl_pps) ? (in_pps - bl_pps) : 0.f;

    ImGui::PushStyleColor(ImGuiCol_Text, ColPps);
    ImGui::Text("Total Ingress: %.0f pps", in_pps);
    ImGui::PopStyleColor();
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Text, ColText2);
    ImGui::TextUnformatted("|");
    ImGui::PopStyleColor();
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Text, ColBlocks);
    ImGui::Text("Mitigated: %.0f/s", bl_pps);
    ImGui::PopStyleColor();
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Text, ColText2);
    ImGui::TextUnformatted("|");
    ImGui::PopStyleColor();
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Text, ColCyan);
    ImGui::Text("Passed: %.0f pps", cl_pps);
    ImGui::PopStyleColor();
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Text, ColText2);
    ImGui::TextUnformatted("|");
    ImGui::PopStyleColor();
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Text, ColText1);
    char tot_buf[32];
    fmt_num(tot_buf, sizeof(tot_buf), total_10m_traffic > 0 ? total_10m_traffic : s.traffic);
    ImGui::Text("Total: %s", tot_buf);
    ImGui::PopStyleColor();

    ImVec2 p0 = ImGui::GetCursorScreenPos();
    float w = ImGui::GetContentRegionAvail().x;
    if (w < 80.f) w = 80.f;
    const float h = 118.f;
    const float left_m = 44.f;
    const float bottom_m = 18.f;
    const float plot_w = w - left_m - 8.f;
    const float plot_h = h - bottom_m - 6.f;

    ImGui::InvisibleButton("##chart10m", ImVec2(w, h));
    bool hovered = ImGui::IsItemHovered();
    ImVec2 mouse_pos = ImGui::GetIO().MousePos;

    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(p0, ImVec2(p0.x + w, p0.y + h), ImGui::ColorConvertFloat4ToU32(ColBg1), 8.f);
    dl->AddRect(p0, ImVec2(p0.x + w, p0.y + h), ImGui::ColorConvertFloat4ToU32(ColGlassBorder), 8.f);

    if (count < 2) {
        dl->AddText(ImVec2(p0.x + left_m + 20, p0.y + h * 0.4f), ImGui::ColorConvertFloat4ToU32(ColText2), "Loading telemetry data...");
        return;
    }

    unsigned long long max_tr = 100;
    for (size_t i = 0; i < count; i++) {
        unsigned long long pt_tr = (selected_port > 0) ? (unsigned long long)(data[i].traffic * port_tr_ratio) : data[i].traffic;
        if (pt_tr > max_tr) max_tr = pt_tr;
    }
    unsigned long long max_val = (unsigned long long)(max_tr * 1.15);
    if (max_val < 50) max_val = 50;

    // Grid lines (0%, 50%, 100%)
    for (int step = 0; step <= 2; step++) {
        float y = p0.y + 4.f + (plot_h * (1.f - step / 2.f));
        dl->AddLine(ImVec2(p0.x + left_m, y), ImVec2(p0.x + left_m + plot_w, y),
                    ImGui::ColorConvertFloat4ToU32(ImVec4(1, 1, 1, 0.05f)), 1.f);
        if (step > 0) {
            char y_lbl[16];
            fmt_num(y_lbl, sizeof(y_lbl), (unsigned long long)(max_val * (step / 2.f)));
            dl->AddText(ImVec2(p0.x + 4.f, y - 6.f), ImGui::ColorConvertFloat4ToU32(ColText2), y_lbl);
        }
    }

    float den = (float)(count - 1);
    std::vector<ImVec2> pts_tr(count), pts_bl(count), pts_ps(count);

    for (size_t i = 0; i < count; i++) {
        unsigned long long pt_tr = (selected_port > 0) ? (unsigned long long)(data[i].traffic * port_tr_ratio) : data[i].traffic;
        unsigned long long pt_bl = (selected_port > 0) ? (unsigned long long)(data[i].blocked * port_bl_ratio) : data[i].blocked;
        unsigned long long pt_ps = (pt_tr > pt_bl) ? (pt_tr - pt_bl) : 0;

        float x = p0.x + left_m + ((float)i / den) * plot_w;
        float y_tr = p0.y + 4.f + plot_h - ((float)pt_tr / (float)max_val) * (plot_h - 8.f);
        float y_bl = p0.y + 4.f + plot_h - ((float)pt_bl / (float)max_val) * (plot_h - 8.f);
        float y_ps = p0.y + 4.f + plot_h - ((float)pt_ps / (float)max_val) * (plot_h - 8.f);

        if (pt_bl > 0 && y_bl > (p0.y + 4.f + plot_h - 2.5f)) {
            y_bl = p0.y + 4.f + plot_h - 2.5f;
        }
        if (pt_ps > 0 && y_ps > (p0.y + 4.f + plot_h - 2.5f)) {
            y_ps = p0.y + 4.f + plot_h - 2.5f;
        }

        pts_tr[i] = ImVec2(x, y_tr);
        pts_bl[i] = ImVec2(x, y_bl);
        pts_ps[i] = ImVec2(x, y_ps);
    }

    ImU32 col_traffic = ImGui::ColorConvertFloat4ToU32(ColPps);
    ImU32 col_blocked = ImGui::ColorConvertFloat4ToU32(ColBlocks);
    ImU32 col_passed  = ImGui::ColorConvertFloat4ToU32(ColCyan);

    for (size_t i = 0; i + 1 < count; i++) {
        dl->AddLine(pts_tr[i], pts_tr[i + 1], col_traffic, 2.0f);
        dl->AddLine(pts_ps[i], pts_ps[i + 1], col_passed, 1.8f);
        dl->AddLine(pts_bl[i], pts_bl[i + 1], col_blocked, 1.8f);
    }

    // Time labels on X-axis (every 2 minutes = 12 points)
    for (size_t i = 0; i < count; i += 12) {
        float x = pts_tr[i].x;
        dl->AddText(ImVec2(x - 14.f, p0.y + h - bottom_m + 2.f),
                    ImGui::ColorConvertFloat4ToU32(ColText2), data[i].minute.c_str());
    }
    if (count > 0 && (count - 1) % 12 != 0) {
        float x = pts_tr[count - 1].x;
        dl->AddText(ImVec2(x - 18.f, p0.y + h - bottom_m + 2.f),
                    ImGui::ColorConvertFloat4ToU32(ColText2), data[count - 1].minute.c_str());
    }

    // Interactive Hover Tooltip
    if (hovered && mouse_pos.x >= p0.x + left_m && mouse_pos.x <= p0.x + left_m + plot_w) {
        float rel_x = (mouse_pos.x - (p0.x + left_m)) / plot_w;
        int hover_idx = (int)(rel_x * den + 0.5f);
        if (hover_idx >= 0 && hover_idx < (int)count) {
            float hx = pts_tr[hover_idx].x;
            dl->AddLine(ImVec2(hx, p0.y + 4.f), ImVec2(hx, p0.y + 4.f + plot_h),
                        ImGui::ColorConvertFloat4ToU32(ImVec4(1, 1, 1, 0.35f)), 1.5f);
            dl->AddCircleFilled(pts_tr[hover_idx], 4.f, col_traffic);
            dl->AddCircleFilled(pts_ps[hover_idx], 3.5f, col_passed);
            dl->AddCircleFilled(pts_bl[hover_idx], 3.5f, col_blocked);

            unsigned long long pt_tr = (selected_port > 0) ? (unsigned long long)(data[hover_idx].traffic * port_tr_ratio) : data[hover_idx].traffic;
            unsigned long long pt_bl = (selected_port > 0) ? (unsigned long long)(data[hover_idx].blocked * port_bl_ratio) : data[hover_idx].blocked;

            ImGui::BeginTooltip();
            ImGui::Text("Time: %s", data[hover_idx].minute.c_str());
            ImGui::Separator();
            char tbuf[32], bbuf[32];
            fmt_num(tbuf, sizeof(tbuf), pt_tr);
            fmt_num(bbuf, sizeof(bbuf), pt_bl);
            unsigned long long pt_cl = (pt_tr > pt_bl) ? (pt_tr - pt_bl) : 0;
            char cbuf[32];
            fmt_num(cbuf, sizeof(cbuf), pt_cl);
            ImGui::PushStyleColor(ImGuiCol_Text, ColPps);
            ImGui::Text("Total Ingress: %s pkts", tbuf);
            ImGui::PopStyleColor();
            ImGui::PushStyleColor(ImGuiCol_Text, ColBlocks);
            ImGui::Text("Mitigated: %s pkts", bbuf);
            ImGui::PopStyleColor();
            ImGui::PushStyleColor(ImGuiCol_Text, ColCyan);
            ImGui::Text("Passed: %s pkts", cbuf);
            ImGui::PopStyleColor();
            ImGui::EndTooltip();
        }
    }
}

const char* proto_name(const std::string& p) {
    if (p == "tcp") return "TCP Only";
    if (p == "both") return "TCP+UDP";
    return "UDP Only";
}

int proto_index(const std::string& p) {
    if (p == "tcp") return PROTO_TCP;
    if (p == "both") return PROTO_BOTH;
    return PROTO_UDP;
}

const char* service_name(int port) {
    switch (port) {
        case 80:   return "HTTP";
        case 443:  return "HTTPS";
        case 8080: return "HTTP-alt";
        case 27015:
        case 27016: return "Source";
        default:   return "";
    }
}

// ---------------------------------------------------------------------------
// Tabs — six, same order, same titles as the Windows build.
// ---------------------------------------------------------------------------
enum Tab { TAB_OZET = 0, TAB_PORTLAR, TAB_BANLAR, TAB_OYUNCULAR, TAB_GEO, TAB_AYARLAR };

// ── Overview ────────────────────────────────────────────────────────────────
void draw_ozet(const Snapshot& s, Snapshot& mut, int& selected_port) {
    const ImGuiWindowFlags no_scroll =
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;

    // ── Port Category Selectbox ──
    ImGui::AlignTextToFramePadding();
    ImGui::PushStyleColor(ImGuiCol_Text, ColText1);
    ImGui::TextUnformatted("Port Filter:");
    ImGui::PopStyleColor();
    ImGui::SameLine();
    ImGui::SetNextItemWidth(260);

    char combo_preview[64] = "All Ports (Global)";
    if (selected_port > 0)
        snprintf(combo_preview, sizeof(combo_preview), "Port %d", selected_port);

    if (ImGui::BeginCombo("##chartportselect", combo_preview)) {
        if (ImGui::Selectable("All Ports (Global)", selected_port == 0))
            selected_port = 0;
        for (const auto& p : s.ports) {
            char label[64];
            snprintf(label, sizeof(label), "Port %d (Active)", p.port);
            if (ImGui::Selectable(label, selected_port == p.port))
                selected_port = p.port;
        }
        ImGui::EndCombo();
    }

    unsigned long long disp_traffic = s.traffic;
    unsigned long long disp_passed = s.passed;
    int disp_bans = (int)s.bans.size();
    float disp_cur_pps = s.cur_pps;
    float disp_cur_bps = s.cur_bps;

    if (selected_port > 0) {
        if (s.port_traffic.count(selected_port)) {
            disp_traffic = s.port_traffic.at(selected_port);
            unsigned long long blk = s.port_blocked.count(selected_port) ? s.port_blocked.at(selected_port) : 0;
            disp_passed = disp_traffic >= blk ? disp_traffic - blk : 0;
            disp_cur_pps = s.port_cur_pps.count(selected_port) ? s.port_cur_pps.at(selected_port) : 0.f;
        } else {
            disp_traffic = 0;
            disp_passed = 0;
            disp_bans = 0;
            disp_cur_pps = 0.f;
            disp_cur_bps = 0.f;
        }
    }

    char n1[32], n2[32], n3[32], n4[32];
    fmt_num(n1, sizeof(n1), disp_traffic);
    fmt_num(n2, sizeof(n2), disp_passed);
    snprintf(n3, sizeof(n3), "%d", s.players);
    snprintf(n4, sizeof(n4), "%d", disp_bans);

    if (ImGui::BeginTable("##m1", 4, ImGuiTableFlags_SizingStretchSame | ImGuiTableFlags_NoPadOuterX)) {
        ImGui::TableNextColumn(); metric_card("Traffic", n1);
        ImGui::TableNextColumn(); metric_card("Passed", n2);
        ImGui::TableNextColumn(); metric_card("Players", n3);
        ImGui::TableNextColumn(); metric_card("Bans", n4);
        ImGui::EndTable();
    }

    draw_10m_traffic_chart(s, disp_cur_pps, disp_cur_bps, selected_port);

    // ── Two Side-by-Side Panels: Recent Attacks vs Active Bans ──
    float total_w = ImGui::GetContentRegionAvail().x;
    float panel_w = (total_w - 12.f) * 0.5f;

    // --- Left Panel: Recent Mitigated Attacks / Drops ---
    ImGui::BeginChild("##recent_attacks_panel", ImVec2(panel_w, 0), ImGuiChildFlags_Border);
    ImGui::PushStyleColor(ImGuiCol_Text, ColText0);
    ImGui::TextUnformatted("Recent Blocked Attacks (DPI & Drops)");
    ImGui::PopStyleColor();
    ImGui::Separator();
    ImGui::Spacing();

    if (s.recent_blocks.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, ColText2);
        ImGui::TextUnformatted("No attack events in current window. System clean.");
        ImGui::PopStyleColor();
    } else if (ImGui::BeginTable("##recent_table", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("IP Address", ImGuiTableColumnFlags_WidthStretch, 1.4f);
        ImGui::TableSetupColumn("Attack Vector", ImGuiTableColumnFlags_WidthStretch, 1.2f);
        ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, 65);
        ImGui::TableHeadersRow();

        int recent_row_id = 0;
        for (size_t i = 0; i < s.recent_blocks.size() && recent_row_id < 40; ++i) {
            const std::string& line = s.recent_blocks[s.recent_blocks.size() - 1 - i];
            ImGui::PushID(recent_row_id++);
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            size_t sp = line.find(' ');
            std::string ip = (sp != std::string::npos) ? line.substr(0, sp) : line;
            std::string reason = (sp != std::string::npos) ? line.substr(sp + 1) : "flood/scan";
            trim(reason);
            render_copyable_ip(ip, ip, &ColBad);

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(reason.c_str());

            ImGui::TableNextColumn();
            ImGui::PushStyleColor(ImGuiCol_Text, ColText2);
            ImGui::TextUnformatted("DROPPED");
            ImGui::PopStyleColor();
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    ImGui::EndChild();

    ImGui::SameLine();

    // --- Right Panel: Active Bans with Duration & Quick Unban ---
    ImGui::BeginChild("##active_bans_panel", ImVec2(panel_w, 0), ImGuiChildFlags_Border);
    ImGui::PushStyleColor(ImGuiCol_Text, ColText0);
    ImGui::TextUnformatted("Active Bans");
    ImGui::PopStyleColor();
    ImGui::SameLine(panel_w - 90);
    ImGui::PushStyleColor(ImGuiCol_Text, ColAmber);
    ImGui::Text("%zu active", s.bans.size());
    ImGui::PopStyleColor();
    ImGui::Separator();
    ImGui::Spacing();

    std::string unban_click_ip;
    unsigned int unban_click_port = 0;
    if (s.bans.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, ColText2);
        ImGui::TextUnformatted("No active bans.");
        ImGui::PopStyleColor();
    } else if (ImGui::BeginTable("##quick_bans_table", 4, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("IP / Target", ImGuiTableColumnFlags_WidthStretch, 1.4f);
        ImGui::TableSetupColumn("Remain", ImGuiTableColumnFlags_WidthFixed, 85);
        ImGui::TableSetupColumn("Reason", ImGuiTableColumnFlags_WidthStretch, 1.1f);
        ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, 65);
        ImGui::TableHeadersRow();

        for (size_t i = 0; i < s.bans.size(); ++i) {
            const auto& b = s.bans[i];
            ImGui::PushID((int)(i + 10000));
            ImGui::TableNextRow();

            ImGui::TableNextColumn();
            std::string disp_ip = b.ip;
            if (b.port > 0) disp_ip += ":" + std::to_string(b.port);
            render_copyable_ip(disp_ip, b.ip, &ColBlocks);

            ImGui::TableNextColumn();
            if (b.remain_sec > 0) {
                char dur_buf[32];
                fmt_duration(dur_buf, sizeof(dur_buf), b.remain_sec);
                ImGui::PushStyleColor(ImGuiCol_Text, ColAmber);
                ImGui::TextUnformatted(dur_buf);
                ImGui::PopStyleColor();
            } else {
                ImGui::TextUnformatted("Permanent");
            }

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(b.reason.empty() ? "Auto" : b.reason.c_str());

            ImGui::TableNextColumn();
            if (ghost_button("Unban")) {
                unban_click_ip = b.ip;
                unban_click_port = b.port;
            }
            ImGui::PopID();
        }
        ImGui::EndTable();
        if (!unban_click_ip.empty()) {
            instant_unban(mut, unban_click_ip, unban_click_port);
        }
    }
    ImGui::EndChild();

    (void)mut;
}

// ── Ports ───────────────────────────────────────────────────────────────────
void draw_portlar(Snapshot& s, int& rate_pct) {
    ImGui::BeginChild("##ports", ImVec2(0, 0), ImGuiChildFlags_Border);
    ImGui::TextUnformatted("Ports");
    ImGui::SameLine(ImGui::GetContentRegionAvail().x - 100);
    if (ghost_button("Auto-detect")) {
        trigger_async_refresh();
    }
    ImGui::Separator();
    ImGui::Spacing();

    if (ImGui::BeginTable("##portlist", 9,
                          ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                              ImGuiTableFlags_SizingStretchSame)) {
        ImGui::TableSetupColumn("On", ImGuiTableColumnFlags_WidthFixed, 35);
        ImGui::TableSetupColumn("Port", ImGuiTableColumnFlags_WidthFixed, 65);
        ImGui::TableSetupColumn("Protocol", ImGuiTableColumnFlags_WidthFixed, 95);
        ImGui::TableSetupColumn("Service", ImGuiTableColumnFlags_WidthFixed, 80);
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 75);
        ImGui::TableSetupColumn("Atk", ImGuiTableColumnFlags_WidthFixed, 35);
        ImGui::TableSetupColumn("Rate %", ImGuiTableColumnFlags_WidthStretch, 1.2f);
        ImGui::TableSetupColumn("Mbps", ImGuiTableColumnFlags_WidthStretch, 1.0f);
        ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 35);
        ImGui::TableHeadersRow();

        for (size_t i = 0; i < s.ports.size(); i++) {
            PortRow& p = s.ports[i];
            ImGui::TableNextRow();
            ImGui::PushID((int)i);

            ImGui::TableNextColumn();
            if (ImGui::Checkbox("##en", &p.enabled)) {
                save_ports_config(s.ports);
            }

            ImGui::TableNextColumn();
            ImGui::PushStyleColor(ImGuiCol_Text, p.enabled ? ColOk : ColText2);
            ImGui::Text("%d", p.port);
            ImGui::PopStyleColor();

            ImGui::TableNextColumn();
            ImGui::SetNextItemWidth(-1);
            const char* proto_names[] = {"TCP+UDP", "TCP Only", "UDP Only"};
            int cur_proto = proto_index(p.proto);
            if (ImGui::Combo("##proto", &cur_proto, proto_names, IM_ARRAYSIZE(proto_names))) {
                if (cur_proto == 0) p.proto = "both";
                else if (cur_proto == 1) p.proto = "tcp";
                else if (cur_proto == 2) p.proto = "udp";
                save_ports_config(s.ports);
            }

            ImGui::TableNextColumn();
            {
                const char* svc = service_name(p.port);
                if (svc[0]) {
                    ImGui::TextUnformatted(svc);
                } else {
                    ImGui::PushStyleColor(ImGuiCol_Text, ColText2);
                    ImGui::TextUnformatted("-");
                    ImGui::PopStyleColor();
                }
            }

            ImGui::TableNextColumn();
            ImGui::SetNextItemWidth(-1);
            const char* type_preview = (p.type == TYPE_WEB) ? "Web" : "Game";
            if (ImGui::BeginCombo("##type", type_preview)) {
                if (ImGui::Selectable("Game", p.type == TYPE_GAME)) {
                    p.type = TYPE_GAME;
                    save_ports_config(s.ports);
                }
                if (ImGui::Selectable("Web", p.type == TYPE_WEB)) {
                    p.type = TYPE_WEB;
                    save_ports_config(s.ports);
                }
                ImGui::EndCombo();
            }

            ImGui::TableNextColumn();
            if (ImGui::Checkbox("##atk", &p.attack)) {
                save_ports_config(s.ports);
            }

            ImGui::TableNextColumn();
            ImGui::SetNextItemWidth(-1);
            int rl = p.rate_limit;
            if (ImGui::InputInt("##rl", &rl, 0, 0)) {
                if (rl < 10) rl = 10;
                if (rl > 300) rl = 300;
                p.rate_limit = rl;
                save_ports_config(s.ports);
            }

            ImGui::TableNextColumn();
            ImGui::SetNextItemWidth(-1);
            int sp = p.speed_mbps;
            if (ImGui::InputInt("##mbps", &sp, 0, 0)) {
                if (sp < 0) sp = 0;
                p.speed_mbps = sp;
                save_ports_config(s.ports);
            }

            ImGui::TableNextColumn();
            if (ghost_button("X")) {
                s.ports.erase(s.ports.begin() + i);
                save_ports_config(s.ports);
                ImGui::PopID();
                break;
            }

            ImGui::PopID();
        }
        ImGui::EndTable();
    }

    ImGui::Spacing();
    {
        static int add_port = 0;
        ImGui::SetNextItemWidth(120);
        ImGui::InputInt("##addport", &add_port, 0, 0);
        if (add_port < 0) add_port = 0;
        if (add_port > 65535) add_port = 65535;
        ImGui::SameLine();

        const char* add_type_name = (add_port == 80 || add_port == 443 || add_port == 8080) ? "Web" : "Game";
        ImGui::PushStyleColor(ImGuiCol_Text, ColText2);
        ImGui::Text("(%s)", add_type_name);
        ImGui::PopStyleColor();
        ImGui::SameLine();

        bool can_add = add_port > 0;
        if (!can_add) ImGui::BeginDisabled();
        if (accent_button("Add Port", ImVec2(100, 28))) {
            bool exists = false;
            for (const auto& ep : s.ports) {
                if (ep.port == add_port) { exists = true; break; }
            }
            if (!exists && add_port > 0) {
                PortRow nr;
                nr.port = add_port;
                nr.enabled = true;
                nr.type = (add_port == 80 || add_port == 443 || add_port == 8080) ? TYPE_WEB : TYPE_GAME;
                nr.proto = (nr.type == TYPE_WEB) ? "tcp" : "udp";
                nr.rate_limit = 100;
                nr.speed_mbps = 10000;
                s.ports.push_back(nr);
                save_ports_config(s.ports);
                add_port = 0;
            }
        }
        if (!can_add) ImGui::EndDisabled();
    }

    ImGui::Spacing();
    if (accent_button("Save & restart", ImVec2(160, 36))) {
        save_ports_config(s.ports);
        trigger_async_refresh();
    }
    ImGui::EndChild();

    // ── Global Rate Limit ──
    ImGui::Spacing();
    ImGui::BeginChild("##ratelimit", ImVec2(0, 0), ImGuiChildFlags_Border);
    ImGui::Text("Rate limit  %d%%", rate_pct);
    ImGui::SetNextItemWidth(200);
    if (ImGui::InputInt("##ratelimitslider", &rate_pct, 0, 0)) {
        if (rate_pct < 10) rate_pct = 10;
        if (rate_pct > 300) rate_pct = 300;
    }
    ImGui::EndChild();
}

// ── Bans ────────────────────────────────────────────────────────────────────
void draw_banlar(Snapshot& s, char* ban_ip, size_t ban_ip_cap) {
    ImGui::BeginChild("##banform", ImVec2(0, 56), ImGuiChildFlags_Border);
    ImGui::SetNextItemWidth(260);
    ImGui::InputTextWithHint("##banip", "IP address", ban_ip, ban_ip_cap);
    ImGui::SameLine();
    bool can = ban_ip[0] != '\0';
    if (!can) ImGui::BeginDisabled();
    if (accent_button("Ban", ImVec2(100, 0))) {
        std::string ip_str = ban_ip;
        unsigned int p_num = 0;
        size_t col = ip_str.find(':');
        if (col != std::string::npos) {
            p_num = (unsigned int)atoi(ip_str.substr(col + 1).c_str());
            ip_str = ip_str.substr(0, col);
        }
        instant_ban(s, ip_str, p_num, 3600, p_num > 0 ? "manual port ban" : "manual ban");
        ban_ip[0] = '\0';
    }
    if (!can) ImGui::EndDisabled();
    ImGui::EndChild();

    ImGui::BeginChild("##banlist", ImVec2(0, 0), ImGuiChildFlags_Border);
    if (ImGui::BeginTable("bans", 5, ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_RowBg |
                                      ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("IP", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Port", ImGuiTableColumnFlags_WidthFixed, 70);
        ImGui::TableSetupColumn("Remain", ImGuiTableColumnFlags_WidthFixed, 90);
        ImGui::TableSetupColumn("Reason", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 80);
        ImGui::TableHeadersRow();

        std::string unban_ip;
        unsigned int unban_port = 0;
        for (size_t i = 0; i < s.bans.size(); i++) {
            const BanRow& b = s.bans[i];
            ImGui::PushID((int)i);
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            render_copyable_ip(b.ip, b.ip, &ColAmber);
            ImGui::TableNextColumn();
            if (b.port > 0) {
                ImGui::TextColored(ImVec4(0.35f, 0.85f, 0.95f, 1.0f), "%u", b.port);
            } else {
                ImGui::TextColored(ColText2, "Global");
            }
            ImGui::TableNextColumn();
            char dur_buf[32];
            fmt_duration(dur_buf, sizeof(dur_buf), b.remain_sec);
            ImGui::TextUnformatted(dur_buf);
            ImGui::TableNextColumn();
            ImGui::PushStyleColor(ImGuiCol_Text, ColText1);
            ImGui::TextUnformatted(b.reason.c_str());
            ImGui::PopStyleColor();
            ImGui::TableNextColumn();
            if (ghost_button("Unban")) {
                unban_ip = b.ip;
                unban_port = b.port;
            }
            ImGui::PopID();
        }
        ImGui::EndTable();
        if (!unban_ip.empty()) {
            instant_unban(s, unban_ip, unban_port);
        }
    }
    if (s.bans.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, ColText2);
        ImGui::TextUnformatted("No active bans");
        ImGui::PopStyleColor();
    }
    ImGui::EndChild();
}

// ── Players ─────────────────────────────────────────────────────────────────
void draw_oyuncular(Snapshot& s) {
    ImGui::BeginChild("##players", ImVec2(0, 0), ImGuiChildFlags_Border);
    int player_ban_idx = -1;
    std::string player_ban_ip;
    unsigned int player_ban_port = 0;
    if (ImGui::BeginTable("clients", 6, ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_RowBg |
                                         ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("IP:Port & Player", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Geo", ImGuiTableColumnFlags_WidthFixed, 60);
        ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 90);
        ImGui::TableSetupColumn("PPS", ImGuiTableColumnFlags_WidthFixed, 60);
        ImGui::TableSetupColumn("Idle", ImGuiTableColumnFlags_WidthFixed, 60);
        ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, 70);
        ImGui::TableHeadersRow();

        for (size_t i = 0; i < s.clients.size(); i++) {
            const auto& c = s.clients[i];
            ImGui::PushID((int)i);
            bool connected = (c.state == "CONNECTED");
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            std::string pure_ip = c.pure_ip;
            if (pure_ip.empty()) {
                pure_ip = c.ip_port;
                size_t colon = pure_ip.find(':');
                if (colon != std::string::npos) pure_ip = pure_ip.substr(0, colon);
                size_t sp = pure_ip.find(' ');
                if (sp != std::string::npos) pure_ip = pure_ip.substr(0, sp);
                trim(pure_ip);
            }
            render_copyable_ip(c.ip_port, pure_ip);

            // Geo / Country Code column
            ImGui::TableNextColumn();
            if (c.country == "TR") {
                ImGui::TextColored(ImVec4(0.35f, 0.85f, 0.95f, 1.0f), "[TR]");
            } else if (c.country == "IR") {
                ImGui::TextColored(ImVec4(0.95f, 0.70f, 0.20f, 1.0f), "[IR]");
            } else if (!c.country.empty() && c.country != "--") {
                ImGui::TextColored(ImVec4(0.80f, 0.90f, 0.80f, 1.0f), "[%s]", c.country.c_str());
            } else {
                ImGui::TextColored(ColText2, "--");
            }

            ImGui::TableNextColumn();
            ImGui::PushStyleColor(ImGuiCol_Text, connected ? ColOk : ColAmber);
            ImGui::TextUnformatted(c.state.c_str());
            ImGui::PopStyleColor();
            ImGui::TableNextColumn(); ImGui::Text("%d", c.pps);
            ImGui::TableNextColumn(); ImGui::Text("%ds", c.idle_sec);
            ImGui::TableNextColumn();
            if (accent_button("Ban", ImVec2(60, 22))) {
                player_ban_idx = (int)i;
                player_ban_ip = c.pure_ip;
                player_ban_port = c.server_port > 0 ? (unsigned int)c.server_port : 27015;
                if (player_ban_ip.empty()) {
                    player_ban_ip = c.ip_port;
                    size_t colon = player_ban_ip.find(':');
                    if (colon != std::string::npos) player_ban_ip = player_ban_ip.substr(0, colon);
                    size_t sp = player_ban_ip.find(' ');
                    if (sp != std::string::npos) player_ban_ip = player_ban_ip.substr(0, sp);
                    trim(player_ban_ip);
                }
            }
            ImGui::PopID();
        }
        ImGui::EndTable();
        if (player_ban_idx >= 0 && !player_ban_ip.empty()) {
            instant_ban(s, player_ban_ip, player_ban_port, 300, "player ban (5m)");
        }
    }
    if (s.clients.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, ColText2);
        ImGui::TextUnformatted("No active players");
        ImGui::PopStyleColor();
    }
    ImGui::EndChild();
}

// ── Geo ────────────────────────────────────────────────────────────────     
struct CountryEntry { const char* name; const char* code; };
const CountryEntry kCountries[] = {
    {"Turkey (TR)", "TR"}, {"United States (US)", "US"}, {"Germany (DE)", "DE"},
    {"Russia (RU)", "RU"}, {"United Kingdom (GB)", "GB"}, {"France (FR)", "FR"},
    {"Netherlands (NL)", "NL"}, {"China (CN)", "CN"}, {"Brazil (BR)", "BR"},
    {"Canada (CA)", "CA"}, {"Japan (JP)", "JP"}, {"Afghanistan (AF)", "AF"},
    {"Albania (AL)", "AL"}, {"Algeria (DZ)", "DZ"}, {"Andorra (AD)", "AD"},
    {"Angola (AO)", "AO"}, {"Argentina (AR)", "AR"}, {"Armenia (AM)", "AM"},
    {"Australia (AU)", "AU"}, {"Austria (AT)", "AT"}, {"Azerbaijan (AZ)", "AZ"},
    {"Bahamas (BS)", "BS"}, {"Bahrain (BH)", "BH"}, {"Bangladesh (BD)", "BD"},
    {"Belarus (BY)", "BY"}, {"Belgium (BE)", "BE"}, {"Bolivia (BO)", "BO"},
    {"Bosnia & Herzegovina (BA)", "BA"}, {"Bulgaria (BG)", "BG"}, {"Chile (CL)", "CL"},
    {"Colombia (CO)", "CO"}, {"Costa Rica (CR)", "CR"}, {"Croatia (HR)", "HR"},
    {"Cuba (CU)", "CU"}, {"Cyprus (CY)", "CY"}, {"Czech Republic (CZ)", "CZ"},
    {"Denmark (DK)", "DK"}, {"Ecuador (EC)", "EC"}, {"Egypt (EG)", "EG"},
    {"Estonia (EE)", "EE"}, {"Finland (FI)", "FI"}, {"Georgia (GE)", "GE"},
    {"Greece (GR)", "GR"}, {"Hong Kong (HK)", "HK"}, {"Hungary (HU)", "HU"},
    {"Iceland (IS)", "IS"}, {"India (IN)", "IN"}, {"Indonesia (ID)", "ID"},
    {"Iran (IR)", "IR"}, {"Iraq (IQ)", "IQ"}, {"Ireland (IE)", "IE"},
    {"Israel (IL)", "IL"}, {"Italy (IT)", "IT"}, {"Jordan (JO)", "JO"},
    {"Kazakhstan (KZ)", "KZ"}, {"Kenya (KE)", "KE"}, {"Kuwait (KW)", "KW"},
    {"Latvia (LV)", "LV"}, {"Lebanon (LB)", "LB"}, {"Lithuania (LT)", "LT"},
    {"Luxembourg (LU)", "LU"}, {"Malaysia (MY)", "MY"}, {"Mexico (MX)", "MX"},
    {"Moldova (MD)", "MD"}, {"Monaco (MC)", "MC"}, {"Montenegro (ME)", "ME"},
    {"Morocco (MA)", "MA"}, {"New Zealand (NZ)", "NZ"}, {"Nigeria (NG)", "NG"},
    {"North Macedonia (MK)", "MK"}, {"Norway (NO)", "NO"}, {"Oman (OM)", "OM"},
    {"Pakistan (PK)", "PK"}, {"Panama (PA)", "PA"}, {"Paraguay (PY)", "PY"},
    {"Peru (PE)", "PE"}, {"Philippines (PH)", "PH"}, {"Poland (PL)", "PL"},
    {"Portugal (PT)", "PT"}, {"Qatar (QA)", "QA"}, {"Romania (RO)", "RO"},
    {"Saudi Arabia (SA)", "SA"}, {"Serbia (RS)", "RS"}, {"Singapore (SG)", "SG"},
    {"Slovakia (SK)", "SK"}, {"Slovenia (SI)", "SI"}, {"South Africa (ZA)", "ZA"},
    {"South Korea (KR)", "KR"}, {"Spain (ES)", "ES"}, {"Sweden (SE)", "SE"},
    {"Switzerland (CH)", "CH"}, {"Taiwan (TW)", "TW"}, {"Thailand (TH)", "TH"},
    {"Tunisia (TN)", "TN"}, {"Ukraine (UA)", "UA"}, {"United Arab Emirates (AE)", "AE"},
    {"Uruguay (UY)", "UY"}, {"Uzbekistan (UZ)", "UZ"}, {"Venezuela (VE)", "VE"},
    {"Vietnam (VN)", "VN"}, {"Custom IP / Range", "CUSTOM"},
};

void draw_geo(Snapshot& s) {
    static int selected_country = 0;
    static int selected_action = 1; // Block by default
    static int pending_delete = -1; // deferred delete index

    // Process deferred delete from previous frame
    if (pending_delete >= 0) {
        if ((size_t)pending_delete < s.geo_rules.size()) {
            s.geo_rules.erase(s.geo_rules.begin() + pending_delete);
            save_geo_rules(s.geo_rules);
        }
        pending_delete = -1;
    }

    // Filter out "CUSTOM" from the country list for the combo
    const int country_count_raw = IM_ARRAYSIZE(kCountries);
    int country_count = 0;
    for (int i = 0; i < country_count_raw; i++) {
        if (strcmp(kCountries[i].code, "CUSTOM") != 0) country_count++;
    }
    if (selected_country < 0 || selected_country >= country_count) selected_country = 0;
    if (selected_action < 0 || selected_action > 3) selected_action = 1;

    // Build filtered index
    int filtered_idx = 0;
    int real_idx = 0;
    for (int i = 0; i < country_count_raw; i++) {
        if (strcmp(kCountries[i].code, "CUSTOM") == 0) continue;
        if (filtered_idx == selected_country) { real_idx = i; break; }
        filtered_idx++;
    }

    ImGui::BeginChild("##geo_add", ImVec2(0, 88), ImGuiChildFlags_Border);
    ImGui::TextUnformatted("Add rule");
    ImGui::Separator();

    ImGui::SetNextItemWidth(200);
    if (ImGui::BeginCombo("##country_select", kCountries[real_idx].name)) {
        int fi = 0;
        for (int i = 0; i < country_count_raw; i++) {
            if (strcmp(kCountries[i].code, "CUSTOM") == 0) continue;
            bool selected = (fi == selected_country);
            if (ImGui::Selectable(kCountries[i].name, selected))
                selected_country = fi;
            fi++;
        }
        ImGui::EndCombo();
    }

    ImGui::SameLine(0, 8);

    ImGui::SetNextItemWidth(120);
    const char* actions[] = {"Allow", "Block", "Rate limit", "Under attack"};
    ImGui::Combo("##action_select", &selected_action, actions, IM_ARRAYSIZE(actions));
    ImGui::SameLine(0, 8);
    if (accent_button("Add", ImVec2(70, 0))) {
        std::string cc = kCountries[real_idx].code;
        std::string cname = kCountries[real_idx].name;
        bool found = false;
        for (auto& r : s.geo_rules) {
            if (r.code == cc) {
                r.action = selected_action;
                found = true;
                break;
            }
        }
        if (!found) {
            CountryRule r;
            r.code = cc;
            r.name = cname;
            r.action = selected_action;
            r.max_pps = 0;
            r.max_conns = 0;
            r.block_udp = false;
            s.geo_rules.push_back(r);
        }
        save_geo_rules(s.geo_rules);
    }
    ImGui::EndChild();

    // ── Country rules ──
    ImGui::BeginChild("##geo_rules", ImVec2(0, 0), ImGuiChildFlags_Border);
    ImGui::TextUnformatted("Country rules");
    ImGui::Separator();
    if (s.geo_rules.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, ColText2);
        ImGui::TextUnformatted("No country rules configured yet - add above");
        ImGui::PopStyleColor();
    } else if (ImGui::BeginTable("##geotbl", 8,
                                 ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_RowBg |
                                     ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Country", ImGuiTableColumnFlags_WidthStretch, 1.6f);
        ImGui::TableSetupColumn("Code", ImGuiTableColumnFlags_WidthFixed, 48);
        ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, 120);
        ImGui::TableSetupColumn("PPS", ImGuiTableColumnFlags_WidthFixed, 70);
        ImGui::TableSetupColumn("Conns", ImGuiTableColumnFlags_WidthFixed, 70);
        ImGui::TableSetupColumn("UDP", ImGuiTableColumnFlags_WidthFixed, 40);
        ImGui::TableSetupColumn("Rx/Blk", ImGuiTableColumnFlags_WidthStretch, 1.f);
        ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 35);
        ImGui::TableHeadersRow();

        for (size_t i = 0; i < s.geo_rules.size(); i++) {
            CountryRule& r = s.geo_rules[i];
            ImGui::PushID((int)i);
            ImGui::TableNextRow();

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(r.name.empty() ? r.code.c_str() : r.name.c_str());

            ImGui::TableNextColumn();
            ImGui::PushStyleColor(ImGuiCol_Text, ColCyan);
            ImGui::TextUnformatted(r.code.c_str());
            ImGui::PopStyleColor();

            ImGui::TableNextColumn();
            const char* action_names[] = {"Allow", "Block", "Rate limit", "Under attack"};
            int current_action = r.action;
            if (current_action < 0) current_action = 0;
            if (current_action > 3) current_action = 3;
            ImGui::SetNextItemWidth(-1);
            if (ImGui::Combo("##act", &current_action, action_names, IM_ARRAYSIZE(action_names))) {
                r.action = current_action;
                save_geo_rules(s.geo_rules);
            }

            ImGui::TableNextColumn();
            int pps_val = (int)r.max_pps;
            ImGui::SetNextItemWidth(-1);
            if (ImGui::InputInt("##pps", &pps_val, 0, 0)) {
                if (pps_val < 0) pps_val = 0;
                r.max_pps = (unsigned)pps_val;
                save_geo_rules(s.geo_rules);
            }

            ImGui::TableNextColumn();
            int conn_val = (int)r.max_conns;
            ImGui::SetNextItemWidth(-1);
            if (ImGui::InputInt("##conns", &conn_val, 0, 0)) {
                if (conn_val < 0) conn_val = 0;
                r.max_conns = (unsigned)conn_val;
                save_geo_rules(s.geo_rules);
            }

            ImGui::TableNextColumn();
            if (ImGui::Checkbox("##blkudp", &r.block_udp)) {
                save_geo_rules(s.geo_rules);
            }

            ImGui::TableNextColumn();
            ImGui::Text("%llu / %llu", (unsigned long long)r.rx_packets, (unsigned long long)r.blocked_packets);

            ImGui::TableNextColumn();
            if (ghost_button("X")) {
                pending_delete = (int)i;
            }
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    ImGui::EndChild();
}

// ── Settings ────────────────────────────────────────────────────────────────
// One toggle row in the same idiom as the Windows build: a status word, then a
// Kapat/Ac button that writes through the daemon's CLI.
bool toggle_row(const char* label, const char* key, bool& current, float button_w = 80.f) {
    ImGui::AlignTextToFramePadding();
    bool val = current;
    char chk_id[64];
    snprintf(chk_id, sizeof(chk_id), "##chk_%s", key);
    bool changed = false;
    if (ImGui::Checkbox(chk_id, &val)) {
        current = val;
        set_setting(key, val ? "1" : "0");
        changed = true;
    }
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Text, current ? ColOk : ColText2);
    ImGui::Text("%s", label);
    ImGui::PopStyleColor();
    ImGui::SameLine(220);
    if (current) {
        if (ghost_button("Off", ImVec2(button_w, 26))) {
            set_setting(key, "0");
            current = false;
            changed = true;
        }
    } else {
        if (accent_button("On", ImVec2(button_w, 26))) {
            set_setting(key, "1");
            current = true;
            changed = true;
        }
    }
    return changed;
}

bool draw_ayarlar(Snapshot& s, int& per_ip_pps, int& rate_burst, int& ban_seconds) {
    bool dirty = false;

    ImGui::BeginChild("##fullprotect", ImVec2(0, 100), ImGuiChildFlags_Border,
                      ImGuiWindowFlags_NoScrollbar);
    bool full_val = s.enabled;
    if (ImGui::Checkbox("##full_chk", &full_val)) {
        s.enabled = full_val;
        set_setting("enabled", full_val ? "1" : "0");
        dirty = true;
    }
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Text, s.enabled ? ColOk : ColText2);
    ImGui::TextUnformatted(s.enabled ? "FULL PROTECT  ON" : "FULL PROTECT  OFF");
    ImGui::PopStyleColor();

    ImGui::SameLine(220);
    if (accent_button(s.enabled ? "Turn Off" : "Turn On", ImVec2(100, 28))) {
        set_setting("enabled", s.enabled ? "0" : "1");
        s.enabled = !s.enabled;
        dirty = true;
    }
    ImGui::Spacing();
    ImGui::PushStyleColor(ImGuiCol_Text, ColText2);
    ImGui::TextUnformatted(s.table_present ? "ruleset loaded" : "ruleset NOT loaded");
    ImGui::PopStyleColor();
    ImGui::EndChild();

    ImGui::BeginChild("##prot", ImVec2(0, 236), ImGuiChildFlags_Border,
                      ImGuiWindowFlags_NoScrollbar);
    ImGui::TextUnformatted("Protection Modules");
    ImGui::Separator();
    dirty |= toggle_row("Datacenter filter", "datacenter_filter", s.datacenter_filter);
    dirty |= toggle_row("Geo filter", "geo_enabled", s.geo_enabled);
    dirty |= toggle_row("CTI lookup", "cti_enabled", s.cti_enabled);
    dirty |= toggle_row("Auto ban", "auto_ban", s.auto_ban);
    dirty |= toggle_row("L7 DPI", "dpi_enabled", s.dpi_enabled);
    dirty |= toggle_row("XDP datapath", "xdp_enabled", s.xdp_enabled);
    ImGui::EndChild();

    ImGui::BeginChild("##limits", ImVec2(0, 96), ImGuiChildFlags_Border,
                      ImGuiWindowFlags_NoScrollbar);
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Per-IP pps");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(90);
    if (ImGui::InputInt("##pps", &per_ip_pps, 0, 0)) {
        if (per_ip_pps < 0) per_ip_pps = 0;
    }

    ImGui::SameLine();
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("burst");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(90);
    if (ImGui::InputInt("##burst", &rate_burst, 0, 0)) {
        if (rate_burst < 0) rate_burst = 0;
    }

    ImGui::SameLine();
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("ban secs");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(90);
    if (ImGui::InputInt("##bansecs", &ban_seconds, 0, 0)) {
        if (ban_seconds < 0) ban_seconds = 0;
    }

    ImGui::SameLine();
    if (accent_button("Save", ImVec2(80, 26))) {
        set_setting("per_ip_pps", std::to_string(per_ip_pps));
        set_setting("rate_burst", std::to_string(rate_burst));
        set_setting("ban_seconds", std::to_string(ban_seconds));
        s.per_ip_pps = per_ip_pps;
        s.rate_burst = rate_burst;
        s.ban_seconds = ban_seconds;
        dirty = true;
    }
    ImGui::EndChild();

    return dirty;
}

} // namespace

// ---------------------------------------------------------------------------
// Platform layer: GLFW + OpenGL3 replaces Win32 + DX11.
// ---------------------------------------------------------------------------
int main() {
    if (access("/usr/share/femboi/geoip.dat", R_OK) == 0) {
        g_geo.Load("/usr/share/femboi/geoip.dat");
    } else {
        g_geo.Load("/usr/share/fluxxfw/geoip.dat");
    }

    if (!glfwInit()) {
        fprintf(stderr, "femboi-firewall-gui: glfwInit failed - no graphical session?\n");
        return 1;
    }

    const char* glsl_version = "#version 130";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);

    GLFWwindow* window = glfwCreateWindow(1180, 780, "Femboi Firewall", nullptr, nullptr);
    if (!window) {
        fprintf(stderr, "femboi-firewall-gui: could not create a window\n");
        glfwTerminate();
        return 1;
    }
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;
    apply_theme();
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    Snapshot snap;
    refresh(snap);

    Tab tab = TAB_OZET;
    int selected_chart_port = 0;
    int rate_pct = 100;
    int per_ip_pps = snap.per_ip_pps;
    int rate_burst = snap.rate_burst;
    int ban_seconds = snap.ban_seconds;
    char ban_ip[64] = "";

    std::atomic<bool> bg_running{true};
    std::mutex snap_mtx;
    Snapshot bg_snap = snap;
    std::atomic<bool> snap_ready{false};

    std::thread bg_thread([&]() {
        Snapshot worker_snap = snap;
        while (bg_running.load()) {
            for (int i = 0; i < 15; ++i) {
                usleep(100000);
                if (!bg_running.load()) break;
                if (g_trigger_refresh.exchange(false)) break;
            }
            if (!bg_running.load()) break;
            refresh(worker_snap);
            {
                std::lock_guard<std::mutex> lk(snap_mtx);
                bg_snap = worker_snap;
                snap_ready.store(true);
            }
        }
    });

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();
        if (snap_ready.exchange(false)) {
            std::lock_guard<std::mutex> lk(snap_mtx);
            // Merge bans so manual bans aren't lost if kernel hasn't processed them yet
            for (const auto& b : snap.bans) {
                bool found = false;
                for (const auto& bb : bg_snap.bans) {
                    if (bb.ip == b.ip) { found = true; break; }
                }
                if (!found && b.reason == "Manual GUI Ban") {
                    bg_snap.bans.push_back(b);
                }
            }
            snap = bg_snap;
            if (!ImGui::IsAnyItemActive()) {
                per_ip_pps = snap.per_ip_pps;
                rate_burst = snap.rate_burst;
                ban_seconds = snap.ban_seconds;
            }
        }

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        const ImGuiViewport* vp = ImGui::GetMainViewport();
        ImGui::SetNextWindowPos(vp->WorkPos);
        ImGui::SetNextWindowSize(vp->WorkSize);
        ImGui::Begin("##dash", nullptr,
                     ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                         ImGuiWindowFlags_NoResize);

        ImGui::PushStyleColor(ImGuiCol_Text, ColText0);
        ImGui::SetWindowFontScale(1.25f);
        ImGui::TextUnformatted("Femboi Firewall");
        ImGui::SetWindowFontScale(1.f);
        ImGui::PopStyleColor();

        {
            const bool on = snap.enabled && snap.table_present;
            ImGui::SameLine(0, 16);
            ImGui::PushStyleColor(ImGuiCol_Text, on ? ColOk : ColText2);
            ImGui::TextUnformatted(on ? "PROTECT ON" : "PROTECT OFF");
            ImGui::PopStyleColor();
        }

        ImGui::SameLine(ImGui::GetWindowWidth() - 110);
        if (ghost_button("Refresh")) { trigger_async_refresh(); }

        if (!snap.table_present) {
            ImGui::PushStyleColor(ImGuiCol_Text, ColBad);
            ImGui::TextUnformatted("No ruleset in the kernel - nothing is being filtered");
            ImGui::PopStyleColor();
        } else if (!snap.enabled) {
            ImGui::PushStyleColor(ImGuiCol_Text, ColText2);
            ImGui::TextUnformatted("Full Protect is off - only the ruleset's drop rules apply");
            ImGui::PopStyleColor();
        }

        ImGui::Spacing();
        if (tab_button("Overview", tab == TAB_OZET)) tab = TAB_OZET;
        ImGui::SameLine();
        if (tab_button("Ports", tab == TAB_PORTLAR)) tab = TAB_PORTLAR;
        ImGui::SameLine();
        if (tab_button("Bans", tab == TAB_BANLAR)) tab = TAB_BANLAR;
        ImGui::SameLine();
        if (tab_button("Players", tab == TAB_OYUNCULAR)) tab = TAB_OYUNCULAR;
        ImGui::SameLine();
        if (tab_button("Geo", tab == TAB_GEO)) tab = TAB_GEO;
        ImGui::SameLine();
        if (tab_button("Settings", tab == TAB_AYARLAR)) tab = TAB_AYARLAR;

        ImGui::Spacing();
        bool dirty = false;
        switch (tab) {
            case TAB_OZET:      draw_ozet(snap, snap, selected_chart_port); break;
            case TAB_PORTLAR:   draw_portlar(snap, rate_pct); break;
            case TAB_BANLAR:    draw_banlar(snap, ban_ip, sizeof(ban_ip)); break;
            case TAB_OYUNCULAR: draw_oyuncular(snap); break;
            case TAB_GEO:       draw_geo(snap); break;
            default:            dirty = draw_ayarlar(snap, per_ip_pps, rate_burst, ban_seconds); break;
        }
        if (dirty) {
            // Instant in-memory update already applied, config saved in background
            trigger_async_refresh();
        }

        ImGui::End();

        ImGui::Render();
        int w, h;
        glfwGetFramebufferSize(window, &w, &h);
        glViewport(0, 0, w, h);
        glClearColor(ColBg0.x, ColBg0.y, ColBg0.z, 1.f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
        usleep(16000);
    }

    bg_running.store(false);
    g_trigger_refresh.store(true);
    if (bg_thread.joinable()) bg_thread.join();

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();
    return 0;
}
