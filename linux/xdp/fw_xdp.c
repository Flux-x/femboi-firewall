// Femboi Firewall XDP packet filter
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "fw_common.h"

// Banned host address map.
// NOT LRU: an LRU blacklist lets a spoofed-source flood evict the real bans.
// HASH is the correct container for authoritative enforcement state.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct fw_ban_value);
	__uint(max_entries, FW_MAX_BLACKLIST);
} blacklist SEC(".maps");

// Whitelisted host address map.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u8);
	__uint(max_entries, FW_MAX_WHITELIST);
} whitelist SEC(".maps");

// Per-IP rate accounting.
// Deliberately NOT per-CPU: a PERCPU map multiplies the effective limit by the
// CPU count and makes the limit unenforceable. A single shared value gives a
// true per-source total. LRU is acceptable here because rate state is
// disposable (losing an entry only resets a window).
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);
	__type(value, struct fw_rate);
	__uint(max_entries, FW_MAX_RATES);
} rates SEC(".maps");

// Per-port PPS limits, keyed by destination port (only configured ports are
// present; a missing key means "no per-port limit").
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 4096);
} port_limits SEC(".maps");

// Per-(source, destination port) accounting for the per-port limits.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64);
	__type(value, struct fw_rate);
	__uint(max_entries, FW_MAX_RATES);
} port_rates SEC(".maps");

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

// Drop packet and update drop counter.
// The byte-count parameter is named `pkt_bytes` (not `bytes`) so it cannot
// collide with the struct field read on the following line.
#define DROP_COUNT(st, field, pkt_bytes)                  \
	do {                                             \
		if (st) {                                \
			(st)->field++;                   \
			(st)->bytes += (pkt_bytes);      \
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

// Walk the Ethernet header and up to two 802.1Q/802.1ad VLAN tags, returning
// the L3 payload pointer and writing the encapsulated EtherType. Returns NULL
// on a malformed frame. Shared by the IPv4 and IPv6 paths.
static __always_inline void *l3_payload(void *data, void *data_end, __u16 *out_proto)
{
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return NULL;

	__u16 h_proto = eth->h_proto;
	void *nh = (void *)(eth + 1);

#pragma unroll
	for (int i = 0; i < 2; i++) {
		if (h_proto == bpf_htons(ETH_P_8021Q) ||
		    h_proto == bpf_htons(ETH_P_8021AD)) {
			struct vlan_hdr *vh = nh;
			if ((void *)(vh + 1) > data_end)
				return NULL;
			h_proto = vh->h_vlan_encapsulated_proto;
			nh = (void *)(vh + 1);
		} else {
			break;
		}
	}

	*out_proto = h_proto;
	return nh;
}

// Resolve the IPv4 header. Returns NULL if the frame is malformed or not IPv4.
static __always_inline struct iphdr *l3_ipv4(void *data, void *data_end)
{
	__u16 h_proto = 0;
	void *nh = l3_payload(data, data_end, &h_proto);
	if (!nh || h_proto != bpf_htons(ETH_P_IP))
		return NULL;

	struct iphdr *ip = nh;
	if ((void *)(ip + 1) > data_end)
		return NULL;
	return ip;
}

// IPv6 policy. When FW_FLAG_IPV6_DENY is set (the default; `ipv6_enabled=0`),
// drop all IPv6 except essential ICMPv6 control (ND/RA + packet-too-big) so
// neighbour discovery and path MTU still work. Otherwise pass, letting the
// nftables tier apply v6 rate limiting.
static __always_inline int handle_ipv6(void *nh, void *data_end,
				       struct fw_config *cfg, struct fw_stats *st,
				       __u64 bytes)
{
	if (!cfg || !cfg->enabled)
		return XDP_PASS;
	if (!(cfg->flags & FW_FLAG_IPV6_DENY)) {
		count_pass(st, bytes);
		return XDP_PASS;
	}

	struct ipv6hdr *ip6 = nh;
	if ((void *)(ip6 + 1) > data_end)
		return XDP_PASS;

	if (ip6->nexthdr == FW_IPPROTO_ICMPV6) {
		__u8 *icmp6 = (void *)(ip6 + 1);
		if ((void *)icmp6 + 2 <= data_end) {
			const __u8 t = icmp6[0];
			// 2 = packet-too-big (PMTUD), 133/134 = router sol/advert,
			// 135/136 = neighbour sol/advert.
			if (t == 2 || t == 133 || t == 134 || t == 135 || t == 136) {
				count_pass(st, bytes);
				return XDP_PASS;
			}
		}
	}

	DROP_COUNT(st, drop_ipv6, bytes);
}

// Main XDP ingress filter program
SEC("xdp")
int xdp_fw(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct fw_stats *st = get_stats();

	// IPv6 is evaluated before the IPv4 parse so a default-deny policy actually
	// applies in the datapath instead of silently passing every v6 frame.
	{
		__u16 eth_p = 0;
		void *nh = l3_payload(data, data_end, &eth_p);
		if (nh && eth_p == bpf_htons(ETH_P_IPV6))
			return handle_ipv6(nh, data_end, get_config(), st,
					   (__u64)(data_end - data));
	}

	struct iphdr *ip = l3_ipv4(data, data_end);
	if (!ip)
		return XDP_PASS;

	const __u32 saddr = ip->saddr;
	const __u64 bytes = (__u64)(data_end - data);

	const __u32 ihl = (__u32)ip->ihl * 4u;
	if (ihl < 20u || (void *)ip + ihl > data_end)
		DROP_COUNT(st, drop_malformed, bytes);

	// tot_len must be sane and must not claim more than the frame carries
	// (truncated / lying headers are a common evasion).
	const __u16 tot_len = bpf_ntohs(ip->tot_len);
	const __u64 frame_l3 = (__u64)(data_end - (void *)ip);
	if (tot_len < ihl || (__u64)tot_len > frame_l3)
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
			__sync_fetch_and_add(&ban->hits, 1);
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
			// Validate the TCP header length (data offset) before trusting it.
			const __u32 doff = (__u32)tcp->doff * 4u;
			if (doff < 20u || (void *)tcp + doff > data_end)
				DROP_COUNT(st, drop_malformed, bytes);
			dport = bpf_ntohs(tcp->dest);
			is_syn = tcp->syn && !tcp->ack;
		} else if (proto == IPPROTO_UDP) {
			struct udphdr *udp = l4;
			if ((void *)(udp + 1) > data_end)
				DROP_COUNT(st, drop_malformed, bytes);
			// UDP length must cover the header and not exceed the L4 span.
			const __u16 ulen = bpf_ntohs(udp->len);
			if (ulen < 8u || (__u64)ulen > (__u64)(data_end - l4))
				DROP_COUNT(st, drop_malformed, bytes);
			dport = bpf_ntohs(udp->dest);
		}
	}

	__u8 pclass = FW_PORT_UNPROTECTED;
	if (proto == IPPROTO_ICMP) {
		pclass = FW_PORT_GAME;
	} else if (is_fragment) {
		// Non-first fragments carry no L4 header; treat as protected so they
		// cannot bypass the per-source budget.
		pclass = FW_PORT_GAME;
	} else if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) {
		// Protocols other than TCP/UDP (GRE, ESP, SCTP, ...) have no port to
		// classify. Previously they fell through via port_class[0] and were
		// never limited; treat them as protected instead.
		pclass = FW_PORT_GAME;
	} else {
		__u32 key = dport;
		__u8 *pc = bpf_map_lookup_elem(&port_class, &key);
		if (pc)
			pclass = *pc;

		if (pclass == FW_PORT_SYSTEM) {
			count_pass(st, bytes);
			return XDP_PASS;
		}
		if (pclass == FW_PORT_UNPROTECTED) {
			count_pass(st, bytes);
			return XDP_PASS;
		}
	}

	if (proto == IPPROTO_ICMP) {
		// Never drop ICMP destination-unreachable/fragmentation-needed (type 3,
		// code 4): it is required for path MTU discovery.
		if ((void *)ip + ihl + 2 <= data_end) {
			__u8 *icmp = (void *)ip + ihl;
			if (icmp[0] == 3 && icmp[1] == 4) {
				count_pass(st, bytes);
				return XDP_PASS;
			}
		}
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

	// Guard against a misconfigured zero window: `now - start >= 0` is always
	// true, which would reset the counters on every packet and silently disable
	// every per-IP limit. Fall back to a 1s window.
	const __u64 window_ns = cfg->window_ns ? cfg->window_ns : 1000000000ull;
	if (now - r->window_start_ns >= window_ns) {
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

	// Per-port budget (in addition to the per-source budget below).
	if (pclass == FW_PORT_GAME || pclass == FW_PORT_WEB) {
		__u32 pkey = dport;
		__u32 *plim = bpf_map_lookup_elem(&port_limits, &pkey);
		if (plim && *plim) {
			const __u64 ckey = ((__u64)saddr << 16) | dport;
			struct fw_rate *pr = bpf_map_lookup_elem(&port_rates, &ckey);
			if (!pr) {
				struct fw_rate fresh = {
					.window_start_ns = now,
					.last_seen_ns = now,
				};
				bpf_map_update_elem(&port_rates, &ckey, &fresh, BPF_NOEXIST);
				pr = bpf_map_lookup_elem(&port_rates, &ckey);
			}
			if (pr) {
				if (now - pr->window_start_ns >= window_ns) {
					pr->window_start_ns = now;
					pr->pkt = 0;
				}
				pr->last_seen_ns = now;
				pr->pkt++;
				if (pr->pkt > *plim) {
					if (may_ban)
						ban_source(saddr, FW_BAN_PPS, ttl, st);
					DROP_COUNT(st, drop_pps, bytes);
				}
			}
		}
	}

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

// NOTE: there is no XDP egress hook. A previous `xdp_fw_egress` program lived
// here but was meaningless (XDP only runs on ingress) and, because bpftool
// loads the FIRST program in an object file, `--egress` silently re-loaded the
// ingress program. Outbound filtering, if ever required, belongs in a TC
// (SEC("tc"/clsact)) program rather than here.

char LICENSE[] SEC("license") = "GPL";
