// Femboi Firewall unit tests (no kernel / no root required).
//
// Covers the logic that regressed in the security audit:
//   - parse_packet_type split-packet field order (item 24)
//   - BanTable eviction / manual flag / snapshot ordering (items 3, 15, 27)
//   - Config::Load multi-slot retention and Save round-trip (item 14)
#include "fw.hpp"
#include "fw_portable.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <unistd.h>

using namespace femboifw;

static int g_failures = 0;

#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                  \
        }                                                                  \
    } while (0)

static void test_split_packet_order() {
    // 0xFFFFFFFE, split id (4), packet_count=3 (byte 8), packet_index=0 (byte 9),
    // then two size bytes. Packet #0 of a 3-part response must be classified as
    // a normal game packet, not an exploit.
    unsigned char pkt[16] = {0};
    pkt[0] = 0xFE; pkt[1] = 0xFF; pkt[2] = 0xFF; pkt[3] = 0xFF;
    pkt[4] = 0x11; pkt[5] = 0x22; pkt[6] = 0x33; pkt[7] = 0x44;
    pkt[8] = 3;    // total
    pkt[9] = 0;    // index
    CHECK(parse_packet_type(pkt, sizeof(pkt)) == PKT_GAME);

    // packet_index >= packet_count is invalid.
    pkt[9] = 3;
    CHECK(parse_packet_type(pkt, sizeof(pkt)) == PKT_INVALID);

    // A zero total count is invalid, not an exploit.
    pkt[8] = 0;
    pkt[9] = 0;
    CHECK(parse_packet_type(pkt, sizeof(pkt)) == PKT_INVALID);
}

static void test_connless_packet() {
    // 0xFFFFFFFF 'q' => GETCHALLENGE
    unsigned char q[8] = {0xFF, 0xFF, 0xFF, 0xFF, 'q', 0x00, 0x00, 0x00};
    CHECK(parse_packet_type(q, sizeof(q)) == PKT_GETCHALLENGE);
    // 0xFFFFFFFF 'k' => CONNECT
    unsigned char k[8] = {0xFF, 0xFF, 0xFF, 0xFF, 'k', 0x00, 0x00, 0x00};
    CHECK(parse_packet_type(k, sizeof(k)) == PKT_CONNECT);
}

static void test_bantable() {
    BanTable bt;
    const uint32_t ip = 0x01020304;  // 1.2.3.4 (network order)
    const int64_t now = NowEpoch();

    bt.Add(ip, 0, "test", 60);
    CHECK(bt.Contains(ip, now));
    CHECK(bt.size() == 1);

    // Manual escalation on an existing permanent record must stick.
    uint32_t perm = 0x05060708;
    bt.Add(perm, 0, "perm", 0, 1, false);
    bt.Add(perm, 0, "perm", 0, 1, true);
    const auto snap = bt.Snapshot(now, 100);
    bool found_manual = false;
    for (const auto& e : snap) {
        if (e.ip_nbo == perm && e.manual) found_manual = true;
    }
    CHECK(found_manual);

    // Sweep removes expired entries.
    bt.Sweep(now + 3600);
    CHECK(!bt.Contains(ip, now + 3600));
}

static void test_ban_store_roundtrip() {
    char path[] = "/tmp/femboi_banstoreXXXXXX";
    const int fd = mkstemp(path);
    CHECK(fd >= 0);
    if (fd < 0) return;
    close(fd);

    const int64_t now = NowEpoch();
    {
        BanTable bt;
        bt.SetStorePath(path);
        bt.Add(0x0A000001, 0, "perm-tag", 0, 1, true);   // 10.0.0.1 permanent
        bt.Add(0x0A000002, 0, "temp", 3600);            // 10.0.0.2 for 1h
    }

    BanTable re;
    re.SetStorePath(path);
    CHECK(re.Restore());
    CHECK(re.size() == 2);
    CHECK(re.Contains(0x0A000001, now));
    CHECK(re.Contains(0x0A000002, now));

    // A manual flag must survive the round-trip.
    const auto snap = re.Snapshot(now, 10);
    bool manual_kept = false;
    for (const auto& e : snap) {
        if (e.ip_nbo == 0x0A000001 && e.manual) manual_kept = true;
    }
    CHECK(manual_kept);

    unlink(path);
}

static void test_config_roundtrip() {
    char path[] = "/tmp/femboi_test_cfgXXXXXX";
    const int fd = mkstemp(path);
    CHECK(fd >= 0);
    if (fd < 0) return;
    close(fd);

    {
        std::ofstream out(path, std::ios::trunc);
        out << "enabled=1\n"
            // Two slot entries with NO preceding `ports=` line: the parser used
            // to wipe the table on each slot line and keep only the last.
            << "slot0=27015 1 0 0 100 10000 0\n"
            << "slot1=443 1 1 0 50 5000 1\n"
            << "whitelist=203.0.113.7, 10.0.0.0/8\n"
            << "ban_seconds=120\n";
    }

    Config cfg;
    std::string err;
    CHECK(cfg.Load(path, &err));
    int enabled_slots = 0;
    for (const auto& p : cfg.ports) {
        if (p.enabled && p.port != 0) ++enabled_slots;
    }
    CHECK(enabled_slots == 2);  // both slots retained
    CHECK(cfg.whitelist.size() == 2);
    CHECK(cfg.ban_seconds == 120);

    // Save must be able to create a brand-new destination and round-trip.
    std::string out_path = std::string(path) + ".out";
    unlink(out_path.c_str());
    CHECK(cfg.Save(out_path, &err));

    Config re;
    CHECK(re.Load(out_path, &err));
    int re_slots = 0;
    for (const auto& p : re.ports) {
        if (p.enabled && p.port != 0) ++re_slots;
    }
    CHECK(re_slots == 2);

    unlink(path);
    unlink(out_path.c_str());
}

int main() {
    test_split_packet_order();
    test_connless_packet();
    test_bantable();
    test_ban_store_roundtrip();
    test_config_roundtrip();

    if (g_failures == 0) {
        std::printf("all tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d test(s) failed\n", g_failures);
    return 1;
}
