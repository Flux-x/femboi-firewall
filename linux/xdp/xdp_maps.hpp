#pragma once
// Femboi Firewall XDP map interface

#include <linux/bpf.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#include "fw_common.h"
#include "fw.hpp"
#include "proc.hpp"

namespace femboifw {

inline constexpr const char* kXdpPinDir = "/sys/fs/bpf/femboifw";
inline constexpr const char* kXdpProgPin = "/sys/fs/bpf/femboifw/prog";
inline constexpr const char* kXdpProgPinEgress = "/sys/fs/bpf/femboifw/prog_egress";

namespace bpf_sys {

// Get monotonic time in nanoseconds
inline uint64_t monotonic_ns() {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

// Low-level bpf syscall invocation
inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr* attr) {
    return (int)syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

// Retrieve pinned BPF object fd
inline int obj_get(const char* path) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.pathname = (__u64)(unsigned long)path;
    return sys_bpf(BPF_OBJ_GET, &attr);
}

// Update entry in BPF map
inline int map_update(int fd, const void* key, const void* value, uint64_t flags) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (__u32)fd;
    attr.key = (__u64)(unsigned long)key;
    attr.value = (__u64)(unsigned long)value;
    attr.flags = (__u32)flags;
    return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr);
}

// Look up entry in BPF map
inline int map_lookup(int fd, const void* key, void* value) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (__u32)fd;
    attr.key = (__u64)(unsigned long)key;
    attr.value = (__u64)(unsigned long)value;
    return sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr);
}

// Delete entry from BPF map
inline int map_delete(int fd, const void* key) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (__u32)fd;
    attr.key = (__u64)(unsigned long)key;
    return sys_bpf(BPF_MAP_DELETE_ELEM, &attr);
}

// Iterate to next BPF map key
inline int map_next_key(int fd, const void* key, void* next) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (__u32)fd;
    attr.key = (__u64)(unsigned long)key;
    attr.next_key = (__u64)(unsigned long)next;
    return sys_bpf(BPF_MAP_GET_NEXT_KEY, &attr);
}

// Retrieve metadata info for map
inline int map_get_info(int fd, struct bpf_map_info* info) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.info.bpf_fd = (__u32)fd;
    attr.info.info_len = sizeof(*info);
    attr.info.info = (__u64)(unsigned long)info;
    return sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr);
}

} // namespace bpf_sys

// Wrapper class for pinned XDP maps
struct XdpMaps {
    int blacklist = -1;
    int whitelist = -1;
    int rates = -1;
    int cfg = -1;
    int stats = -1;
    int port_class = -1;
    std::string pin_dir = kXdpPinDir;

    bool attached() const { return prog >= 0; }
    int prog = -1;

    void Close() {
        for (int* fd : {&blacklist, &whitelist, &rates, &cfg, &stats, &port_class, &prog}) {
            if (*fd >= 0) {
                close(*fd);
                *fd = -1;
            }
        }
    }

    // Open pinned BPF maps from directory
    bool Open(const std::string& dir, std::string* err) {
        pin_dir = dir;
        struct {
            const char* name;
            int* fd;
        } entries[] = {
            {"blacklist", &blacklist}, {"whitelist", &whitelist},
            {"rates", &rates},         {"fw_cfg", &cfg},
            {"fw_stats_map", &stats},  {"port_class", &port_class},
        };

        for (auto& e : entries) {
            const std::string path = dir + "/" + e.name;
            const int fd = bpf_sys::obj_get(path.c_str());
            if (fd < 0) {
                if (err) {
                    *err = "cannot open pinned map " + path;
                }
                Close();
                return false;
            }
            *e.fd = fd;
        }

        prog = bpf_sys::obj_get(kXdpProgPin);
        return true;
    }

    // Add IP to XDP blacklist
    bool BlockIp(uint32_t ip_nbo, uint64_t ttl_secs, uint32_t reason,
                 std::string* err = nullptr) {
        if (blacklist < 0) {
            if (err) *err = "blacklist map not open";
            return false;
        }
        struct fw_ban_value v;
        memset(&v, 0, sizeof(v));
        if (ttl_secs > 0) {
            v.expires_ns = bpf_sys::monotonic_ns() + ttl_secs * 1000000000ull;
        }
        v.reason = reason;
        if (bpf_sys::map_update(blacklist, &ip_nbo, &v, BPF_ANY) != 0) {
            if (err) *err = std::string("blacklist update: ") + strerror(errno);
            return false;
        }
        return true;
    }

    // Remove IP from XDP blacklist
    bool UnblockIp(uint32_t ip_nbo, std::string* err = nullptr) {
        if (blacklist < 0) {
            if (err) *err = "blacklist map not open";
            return false;
        }
        if (bpf_sys::map_delete(blacklist, &ip_nbo) != 0 && errno != ENOENT) {
            if (err) *err = std::string("blacklist delete: ") + strerror(errno);
            return false;
        }
        return true;
    }

    struct BanRow {
        uint32_t ip_nbo;
        uint64_t expires_ns;
        uint32_t reason;
        uint32_t hits;
    };

    // List entries currently in blacklist
    std::vector<BanRow> ListBlocked(size_t limit) const {
        std::vector<BanRow> out;
        if (blacklist < 0) return out;

        uint32_t key = 0;
        uint32_t next = 0;
        struct fw_ban_value v;
        const void* k = nullptr;
        while (out.size() < limit) {
            if (bpf_sys::map_next_key(blacklist, k, &next) != 0) break;
            if (bpf_sys::map_lookup(blacklist, &next, &v) == 0) {
                out.push_back(BanRow{next, v.expires_ns, v.reason, v.hits});
            }
            key = next;
            k = &key;
        }
        return out;
    }

    // Delete all entries in blacklist
    bool FlushBlacklist() {
        if (blacklist < 0) return false;
        uint32_t key = 0;
        uint32_t next = 0;
        const void* k = nullptr;
        for (;;) {
            if (bpf_sys::map_next_key(blacklist, k, &next) != 0) break;
            if (bpf_sys::map_delete(blacklist, &next) != 0) break;
            key = next;
            k = &key;
        }
        return true;
    }

    size_t BlacklistCount(size_t cap = 1000000) const {
        return ListBlocked(cap).size();
    }

    // Add IP to whitelist
    bool AllowIp(uint32_t ip_nbo) {
        if (whitelist < 0) return false;
        const uint8_t one = 1;
        return bpf_sys::map_update(whitelist, &ip_nbo, &one, BPF_ANY) == 0;
    }

    // Remove IP from whitelist
    bool DisallowIp(uint32_t ip_nbo) {
        if (whitelist < 0) return false;
        return bpf_sys::map_delete(whitelist, &ip_nbo) == 0 || errno == ENOENT;
    }

    // List entries in whitelist map
    std::vector<uint32_t> ListAllowed(size_t limit) const {
        std::vector<uint32_t> out;
        if (whitelist < 0) return out;
        uint32_t key = 0;
        uint32_t next = 0;
        uint8_t v = 0;
        const void* k = nullptr;
        while (out.size() < limit) {
            if (bpf_sys::map_next_key(whitelist, k, &next) != 0) break;
            if (bpf_sys::map_lookup(whitelist, &next, &v) == 0) out.push_back(next);
            key = next;
            k = &key;
        }
        return out;
    }

    // Read active config structure
    bool GetConfig(struct fw_config* out) const {
        if (cfg < 0) return false;
        const uint32_t zero = 0;
        return bpf_sys::map_lookup(cfg, &zero, out) == 0;
    }

    // Write updated config structure
    bool SetConfig(const struct fw_config& in) const {
        if (cfg < 0) return false;
        const uint32_t zero = 0;
        return bpf_sys::map_update(cfg, &zero, &in, BPF_ANY) == 0;
    }

    // Set port classification type
    bool SetPortClass(uint16_t port, uint8_t cls) {
        if (port_class < 0) return false;
        const uint32_t key = port;
        return bpf_sys::map_update(port_class, &key, &cls, BPF_ANY) == 0;
    }

    // Read port classification type
    bool GetPortClass(uint16_t port, uint8_t* out) const {
        if (port_class < 0) return false;
        const uint32_t key = port;
        return bpf_sys::map_lookup(port_class, &key, out) == 0;
    }

    // Read aggregated packet statistics
    bool ReadStats(struct fw_stats* out) const {
        if (stats < 0) return false;

        const int ncpu = get_nprocs_conf();
        if (ncpu <= 0 || ncpu > 4096) return false;

        std::vector<struct fw_stats> per(ncpu);
        const uint32_t zero = 0;
        if (bpf_sys::map_lookup(stats, &zero, per.data()) != 0) return false;

        struct fw_stats total;
        memset(&total, 0, sizeof(total));
        for (const auto& s : per) {
            total.pass += s.pass;
            total.bytes += s.bytes;
            total.drop_blacklist += s.drop_blacklist;
            total.drop_pps += s.drop_pps;
            total.drop_syn += s.drop_syn;
            total.drop_udp += s.drop_udp;
            total.drop_icmp += s.drop_icmp;
            total.drop_malformed += s.drop_malformed;
            total.drop_system_port += s.drop_system_port;
            total.auto_bans += s.auto_bans;
        }
        *out = total;
        return true;
    }
};

} // namespace femboifw
