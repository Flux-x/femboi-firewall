// Femboi Firewall XDP packet filter
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "fw_common.h"

// Banned host address map
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);
	__type(value, struct fw_ban_value);
	__uint(max_entries, FW_MAX_BLACKLIST);
} blacklist SEC(".maps");

// Whitelisted host address map
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u8);
	__uint(max_entries, FW_MAX_WHITELIST);
} whitelist SEC(".maps");

// Per-CPU rate limit counters
struct {
	__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
	__type(key, __u32);
	__type(value, struct fw_rate);
	__uint(max_entries, FW_MAX_RATES);
} rates SEC(".maps");

// Runtime filter configuration map
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct fw_config);
	__uint(max_entries, 1);
} fw_cfg SEC(".maps");

// Packet filter statistics map
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct fw_stats);
	__uint(max_entries, 1);
} fw_stats_map SEC(".maps");

// Destination port classification table
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u8);
	__uint(max_entries, 65536);
} port_class SEC(".maps");

// Fetch statistics map entry
static __always_inline struct fw_stats *get_stats(void)
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&fw_stats_map, &zero);
}

// Fetch configuration map entry
static __always_inline struct fw_config *get_config(void)
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&fw_cfg, &zero);
}

// Drop packet and update drop counter
#define DROP_COUNT(st, field, bytes)                      \
	do {                                             \
		if (st) {                                \
			(st)->field++;                   \
			(st)->bytes += (bytes);          \
		}                                        \
		return XDP_DROP;                         \
	} while (0)

// Increment passed packet counter
static __always_inline void count_pass(struct fw_stats *st, __u64 bytes)
{
	if (st) {
		st->pass++;
		st->bytes += bytes;
	}
}

// Insert entry into blacklist map
static __always_inline void ban_source(__u32 saddr, __u32 reason, __u64 ttl_ns,
				       struct fw_stats *st)
{
	struct fw_ban_value v = {
		.expires_ns = ttl_ns ? bpf_ktime_get_ns() + ttl_ns : 0,
		.reason = reason,
		.hits = 0,
	};
	bpf_map_update_elem(&blacklist, &saddr, &v, BPF_ANY);
	if (st)
		st->auto_bans++;
}

// Main XDP ingress filter program
SEC("xdp")
int xdp_fw(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct fw_stats *st = get_stats();

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;

	const __u32 saddr = ip->saddr;
	const __u64 bytes = (__u64)(data_end - data);

	const __u32 ihl = (__u32)ip->ihl * 4u;
	if (ihl < 20u || (void *)ip + ihl > data_end)
		DROP_COUNT(st, drop_malformed, bytes);

	if (bpf_ntohs(ip->tot_len) < ihl)
		DROP_COUNT(st, drop_malformed, bytes);

	struct fw_config *cfg = get_config();
	if (!cfg || !cfg->enabled)
		return XDP_PASS;

	if (bpf_map_lookup_elem(&whitelist, &saddr)) {
		count_pass(st, bytes);
		return XDP_PASS;
	}

	const __u64 now = bpf_ktime_get_ns();
	struct fw_ban_value *ban = bpf_map_lookup_elem(&blacklist, &saddr);
	if (ban) {
		if (ban->expires_ns == 0 || ban->expires_ns > now) {
			ban->hits++;
			DROP_COUNT(st, drop_blacklist, bytes);
		}
		bpf_map_delete_elem(&blacklist, &saddr);
	}

	const __u16 frag_off = bpf_ntohs(ip->frag_off);
	const bool is_fragment = (frag_off & 0x1FFFu) != 0;
	__u8 proto = ip->protocol;
	__u16 dport = 0;
	bool is_syn = false;

	if (!is_fragment) {
		void *l4 = (void *)ip + ihl;

		if (proto == IPPROTO_TCP) {
			struct tcphdr *tcp = l4;
			if ((void *)(tcp + 1) > data_end)
				DROP_COUNT(st, drop_malformed, bytes);
			dport = bpf_ntohs(tcp->dest);
			is_syn = tcp->syn && !tcp->ack;
		} else if (proto == IPPROTO_UDP) {
			struct udphdr *udp = l4;
			if ((void *)(udp + 1) > data_end)
				DROP_COUNT(st, drop_malformed, bytes);
			dport = bpf_ntohs(udp->dest);
		}
	}

	__u8 pclass = FW_PORT_UNPROTECTED;
	if (!is_fragment && proto != IPPROTO_ICMP) {
		__u32 key = dport;
		__u8 *pc = bpf_map_lookup_elem(&port_class, &key);
		if (pc)
			pclass = *pc;

		if (pclass == FW_PORT_SYSTEM)
			return XDP_PASS;
		if (pclass == FW_PORT_UNPROTECTED)
			return XDP_PASS;
	} else if (proto == IPPROTO_ICMP) {
		pclass = FW_PORT_GAME;
	} else {
		pclass = FW_PORT_GAME;
	}

	if (proto == IPPROTO_ICMP) {
		if (!(cfg->flags & FW_FLAG_ICMP_ENABLED))
			DROP_COUNT(st, drop_icmp, bytes);
	}

	struct fw_rate *r = bpf_map_lookup_elem(&rates, &saddr);
	if (!r) {
		struct fw_rate fresh = {
			.window_start_ns = now,
			.last_seen_ns = now,
		};
		bpf_map_update_elem(&rates, &saddr, &fresh, BPF_NOEXIST);
		r = bpf_map_lookup_elem(&rates, &saddr);
		if (!r) {
			count_pass(st, bytes);
			return XDP_PASS;
		}
	}

	if (now - r->window_start_ns >= (__u64)cfg->window_ns) {
		r->window_start_ns = now;
		r->pkt = 0;
		r->syn = 0;
		r->udp = 0;
		r->icmp = 0;
	}
	r->last_seen_ns = now;
	r->pkt++;

	if (proto == IPPROTO_TCP && is_syn)
		r->syn++;
	if (proto == IPPROTO_UDP)
		r->udp++;
	if (proto == IPPROTO_ICMP)
		r->icmp++;

	const bool may_ban = (cfg->flags & FW_FLAG_AUTO_BAN) != 0;
	const __u64 ttl = cfg->ban_time_ns;

	if (proto == IPPROTO_TCP && is_syn && cfg->syn_limit &&
	    r->syn > cfg->syn_limit) {
		if (may_ban)
			ban_source(saddr, FW_BAN_SYN, ttl, st);
		DROP_COUNT(st, drop_syn, bytes);
	}

	if (proto == IPPROTO_UDP && cfg->udp_limit && r->udp > cfg->udp_limit) {
		if (may_ban)
			ban_source(saddr, FW_BAN_UDP, ttl, st);
		DROP_COUNT(st, drop_udp, bytes);
	}

	if (proto == IPPROTO_ICMP && cfg->icmp_limit &&
	    r->icmp > cfg->icmp_limit) {
		if (may_ban)
			ban_source(saddr, FW_BAN_ICMP, ttl, st);
		DROP_COUNT(st, drop_icmp, bytes);
	}

	if (cfg->pps_limit && r->pkt > cfg->pps_limit) {
		if (may_ban)
			ban_source(saddr, FW_BAN_PPS, ttl, st);
		DROP_COUNT(st, drop_pps, bytes);
	}

	count_pass(st, bytes);
	return XDP_PASS;
}

// Optional XDP egress accounting program
SEC("xdp")
int xdp_fw_egress(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct fw_stats *st = get_stats();
	if (!st)
		return XDP_PASS;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	count_pass(st, (__u64)(data_end - data));
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
