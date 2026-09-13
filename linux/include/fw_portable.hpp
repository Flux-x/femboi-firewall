#pragma once
// Packet classification and CIDR helpers
#include <arpa/inet.h>
#include <cstdint>
#include <cstring>

// Source engine UDP packet types
enum PacketType {
    PKT_INVALID = 0,
    PKT_GAME,
    PKT_A2S_INFO,
    PKT_A2S_PLAYER_RULES,
    PKT_GETCHALLENGE,
    PKT_CONNECT,
    PKT_EXPLOIT,
    PKT_DISCONNECT
};

// Check for critical payload exploits
inline bool is_critical_exploit(const unsigned char* payload, unsigned int len) {
    if (len < 5) return false;
    if (payload[0] != 0xFF || payload[1] != 0xFF ||
        payload[2] != 0xFF || payload[3] != 0xFF) {
        return false;
    }
    if (len >= 8 && memcmp(payload + 4, "rcon", 4) == 0) return true;
    if (len > 2048) return true;
    return false;
}

// Parse packet payload type
inline PacketType parse_packet_type(const unsigned char* payload, unsigned int len) {
    if (len < 4) return PKT_GAME;

    // Split packet validation
    if (payload[0] == 0xFE && payload[1] == 0xFF && payload[2] == 0xFF && payload[3] == 0xFF) {
        if (len < 12) return PKT_INVALID;

        uint8_t packet_index = payload[8];
        uint8_t packet_count = payload[9];

        if (packet_count == 0) return PKT_EXPLOIT;
        if (packet_index >= packet_count) return PKT_INVALID;

        return PKT_GAME;
    }

    // Out of band packet parsing
    if (payload[0] == 0xFF && payload[1] == 0xFF && payload[2] == 0xFF && payload[3] == 0xFF) {
        if (len < 5) return PKT_GAME;

        if (len == 5 && payload[4] == 0x00) return PKT_GAME;
        if (len >= 8 && memcmp(payload + 4, "rcon", 4) == 0) return PKT_EXPLOIT;
        if (len > 2048) return PKT_EXPLOIT;

        unsigned char type = payload[4];

        if (len >= 14) {
            for (unsigned int i = 4; i + 10 <= len && i < 64; i++) {
                if (memcmp(payload + i, "disconnect", 10) == 0)
                    return PKT_DISCONNECT;
            }
        }
        if (type == 'q') {
            if (len >= 15 && memcmp(payload + 5, "disconnect", 10) == 0)
                return PKT_DISCONNECT;
            return PKT_GETCHALLENGE;
        }
        if (type == 'k') return PKT_CONNECT;
        if (type == 'd') {
            if (len >= 14 && memcmp(payload + 4, "disconnect", 10) == 0)
                return PKT_DISCONNECT;
            return PKT_GAME;
        }
        if (type == 'c' || type == 's' || type == 'e') return PKT_GAME;

        if (payload[4] == 'l' && len > 4096) return PKT_EXPLOIT;

        if (type == 'T') {
            if (len >= 25 && memcmp(payload + 4, "TSource Engine Query", 20) == 0) {
                return PKT_A2S_INFO;
            }
            return PKT_GAME;
        }
        if (type == 'U' || type == 'V') return PKT_A2S_PLAYER_RULES;

        return PKT_GAME;
    }

    if (len > 65507) return PKT_INVALID;
    return PKT_GAME;
}

// Classify incoming packet buffer
inline PacketType classify_packet_type(const unsigned char* payload, unsigned int len) {
    if (len < 4) return PKT_GAME;
    if (payload[0] != 0xFF && payload[0] != 0xFE) return PKT_GAME;
    return parse_packet_type(payload, len);
}

// CIDR network representation
struct CfCidr {
    uint32_t network;
    uint8_t prefix;
};

// Check if IP belongs to CIDR range
inline bool ipv4_in_cidr_host(uint32_t host_ip, uint32_t network, uint8_t prefix) {
    uint32_t mask = prefix >= 32 ? 0xFFFFFFFFu : (prefix == 0 ? 0u : (0xFFFFFFFFu << (32 - prefix)));
    return (host_ip & mask) == (network & mask);
}

// Detect private and loopback addresses
inline bool is_local_or_loopback_ipv4(uint32_t ip_nbo) {
    const uint32_t ip = ntohl(ip_nbo);
    if ((ip & 0xFF000000u) == 0x7F000000u) return true;
    if ((ip & 0xFF000000u) == 0x0A000000u) return true;
    if ((ip & 0xFFF00000u) == 0xAC100000u) return true;
    if ((ip & 0xFFFF0000u) == 0xC0A80000u) return true;
    if ((ip & 0xFFFF0000u) == 0xA9FE0000u) return true;
    if ((ip & 0xFF000000u) == 0x00000000u) return true;
    return false;
}

// Check Cloudflare proxy IP range
inline bool is_cloudflare_ipv4(uint32_t ip_nbo) {
    const uint32_t ip = ntohl(ip_nbo);
    static const CfCidr kRanges[] = {
        { 0xADF53000u, 20 },
        { 0x6715F400u, 22 },
        { 0x6716C800u, 22 },
        { 0x671F0400u, 22 },
        { 0x8D654000u, 18 },
        { 0x6CA2C000u, 18 },
        { 0xBE5DF000u, 20 },
        { 0xBC726000u, 20 },
        { 0xC5EAF000u, 22 },
        { 0xC6298000u, 17 },
        { 0xA29E0000u, 15 },
        { 0x68100000u, 13 },
        { 0x68180000u, 14 },
        { 0xAC400000u, 13 },
        { 0x83004800u, 22 },
    };
    for (const auto& r : kRanges) {
        if (ipv4_in_cidr_host(ip, r.network, r.prefix))
            return true;
    }
    return false;
}

// System management ports table
inline const uint16_t* system_ports_table(size_t* out_count) {
    static const uint16_t kSys[] = {
        22,
    };
    if (out_count) *out_count = sizeof(kSys) / sizeof(kSys[0]);
    return kSys;
}

// Check if port is protected system port
inline bool is_system_port(uint16_t port) {
    size_t n = 0;
    const uint16_t* table = system_ports_table(&n);
    for (size_t i = 0; i < n; ++i) {
        if (table[i] == port) return true;
    }
    return false;
}
