#ifndef FW_COMMON_H
#define FW_COMMON_H

// Shared XDP datapath contract

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#define FW_MAX_BLACKLIST (1u << 20)
#define FW_MAX_WHITELIST (1u << 16)
#define FW_MAX_RATES (1u << 20)

// Destination port classification
#define FW_PORT_UNPROTECTED 0
#define FW_PORT_GAME 1
#define FW_PORT_WEB 2
#define FW_PORT_SYSTEM 3

// Ban reason constants
#define FW_BAN_MANUAL 0
#define FW_BAN_PPS 1
#define FW_BAN_SYN 2
#define FW_BAN_UDP 3
#define FW_BAN_ICMP 4
#define FW_BAN_MALFORMED 5

// Filter configuration flags
#define FW_FLAG_ICMP_ENABLED (1u << 0)
#define FW_FLAG_AUTO_BAN (1u << 1)
#define FW_FLAG_COUNT_BYTES (1u << 2)

// Per IP rate accounting window
struct fw_rate {
	__u64 window_start_ns;
	__u64 last_seen_ns;
	__u32 pkt;
	__u32 syn;
	__u32 udp;
	__u32 icmp;
};

// Blacklist entry metadata
struct fw_ban_value {
	__u64 expires_ns;
	__u32 reason;
	__u32 hits;
};

// Runtime configuration block
struct fw_config {
	__u32 enabled;
	__u32 pps_limit;
	__u32 syn_limit;
	__u32 udp_limit;
	__u32 icmp_limit;
	__u32 window_ns;
	__u64 ban_time_ns;
	__u32 flags;
	__u32 pad;
};

// XDP datapath traffic counters
struct fw_stats {
	__u64 pass;
	__u64 bytes;
	__u64 drop_blacklist;
	__u64 drop_pps;
	__u64 drop_syn;
	__u64 drop_udp;
	__u64 drop_icmp;
	__u64 drop_malformed;
	__u64 drop_system_port;
	__u64 auto_bans;
};

#endif // FW_COMMON_H
