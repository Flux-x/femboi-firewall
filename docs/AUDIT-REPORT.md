# femboi-firewall — Security & Correctness Audit (2026-10-10)

Scope: `linux/src/{nft,main,engine,dpi,util}.cpp`,
`linux/include/{fw,proc,fw_portable,fw_l7_http}.hpp`,
`linux/xdp/{fw_xdp.c,fw_common.h,xdp_maps.hpp,xdpctl.cpp,Makefile}`,
`linux/gui/fw_gui.cpp`, `gui/fw-gui`, `derle.sh`, packaging, CI.

> **Verification disclaimer.** This environment is Windows/Git-Bash with **no
> `g++`, `clang`, `nft`, or `bpftool`**. All changes below were made by static
> review against the sources and the authoritative protocol reference. They
> have **not** been compiled or exercised on a kernel here. The CI workflow
> (`.github/workflows/ci.yml`) is the intended verification harness. Items
> marked ✅ are implemented and self-consistent; ⚠️ are implemented but need
> kernel/toolchain confirmation; ⏸️ are deferred with rationale; ❌ were
> checked and found **not** to be defects.

## Status summary

| # | Area | Status | Where |
|---|------|--------|-------|
| 1 | SSH meter inverted | ✅ Fixed | `nft.cpp` |
| 2 | Spoofable ban triggers | ⚠️ Mitigated (whitelist + rate-gate) | `nft.cpp`, `fw.hpp` |
| 3 | Split-brain ban state | ⚠️ Mitigated (additive sync, TTL, eviction) | `main.cpp`, `engine.cpp`, `nft.cpp` |
| 4 | `established` before meters/DPI | ✅ Fixed | `nft.cpp` |
| 5 | Geo/DC drops before established | ✅ Fixed (`ct state new`) | `nft.cpp` |
| 6 | IPv6 handling | ⚠️ Handled (ICMPv6 + explicit unmanaged pass) | `nft.cpp` |
| 7 | XDP not driven by config | ⚠️ Fixed (fw_cfg mapping) | `main.cpp` |
| 8 | `get_nprocs_conf` for per-CPU map | ✅ Fixed | `xdp_maps.hpp` |
| 9 | LRU/per-CPU rates design | ⏸️ Deferred (design) | report |
| 10 | XDP datapath hardening | ⚠️ Partial | `fw_xdp.c`, `fw_common.h` |
| 11 | Meaningless XDP egress | ✅ Removed | `fw_xdp.c`, `xdpctl.cpp` |
| 12 | xdpctl detach/pin-dir/reboot | ✅ Fixed | `xdpctl.cpp`, `xdp_maps.hpp` |
| 13 | README/config schema | ✅ Fixed + unknown-key warning | `README.md`, `firewall.conf.example`, `engine.cpp` |
| 14 | Config Load/Save fidelity | ✅ Fixed | `engine.cpp` |
| 15 | Reload path / race / geo / DPI lifecycle | ⚠️ Partial | `main.cpp` |
| 16 | CmdStatus/CmdList/CmdGeo/CmdBan | ⚠️ Partial | `main.cpp` |
| 17 | Dead settings | ⚠️ Partial (`cti_enabled` removed) | `engine.cpp`, `main.cpp` |
| 18 | nft flush/sync/refactor | ✅ Fixed | `nft.cpp` |
| 19 | `EnsureTcLatency` | ✅ Removed | `main.cpp` |
| 20 | Runtime sysctl writes | ✅ Fixed (drop-in file) | `main.cpp`, `debian/` |
| 21 | Shutdown lifecycle policy | ✅ Decided (retain) | `main.cpp`, `debian/*.prerm` |
| 22 | `DpiAvailable` link error | ✅ Fixed | `dpi.cpp` |
| 23 | nfqueue robustness | ⚠️ Partial | `dpi.cpp` |
| 24 | Split-packet offsets | ✅ Fixed (verified) | `fw_portable.hpp` |
| 25 | L7 false positives / CPU | ⏸️ Deferred | report |
| 26 | `proc.hpp` spawn hardening | ✅ Fixed | `proc.hpp` |
| 27 | util/engine hardening | ⚠️ Partial | `engine.cpp`, `util.cpp` |
| 28 | xdp_maps fd/port_class | ⚠️ Partial | `xdp_maps.hpp` |
| 29 | GUI root/config/socket | ⏸️ Deferred | report |
| 30 | Python GUI rename remnants | ⏸️ Deferred | report |
| 31 | Build/install script | ✅ Fixed | `derle.sh` |
| 32 | Repo hygiene / geoip provenance | ⚠️ Partial | `tools/geoip/README.md` |
| 33 | CI | ✅ Added | `.github/workflows/ci.yml` |
| 34 | `.deb` packaging | ✅ Added | `debian/` |
| 35 | nftables.service / hook conflicts | ⏸️ Needs ops test | report |
| 36 | Debian 11/12/13 specifics | ⚠️ Partial | `nft.cpp`, `xdpctl.cpp` |
| 37 | Hardcoded `ens192` | ✅ Addressed (removed) | `main.cpp` |
| 38 | XDP persistence across reboot | ⚠️ Partial | `deploy/*.service` |
| 39 | Update timers / AppArmor / version | ⏸️ Deferred | report |

---

## A. Critical

### 1. SSH rule inverted — ✅ FIXED
**Root cause.** `nft.cpp` emitted `... } accept` for the meter-overflow branch
and `... update @banned ... drop` unconditionally for every *new* SSH packet,
so normal first connections were banned while floods were accepted.
**Fix.** One rule: only the meter-overflow branch is banned+dropped, and normal
new SSH falls through to accept.
**Test.** `femboi-firewall ruleset | nft -c -f -`; on a VM, three rapid
`ssh` attempts within the limit must all connect.

### 2. Ban triggers spoofable — ⚠️ MITIGATED
**Root cause.** Management-port, SSH, and portscan rules banned on a single
packet without any handshake proof, so a spoofed SYN could blackhole an
arbitrary (admin/player) address; the sensitive-port list would ban anyone
using them.
**Fix.** Added a `whitelist` interval set consulted first (config
`whitelist=`, admin IPs); management-port and SSH auto-bans are gated behind
`ct state new` **and** a rate meter so a single packet cannot trigger a ban;
`auto_ban` now maps to XDP flags too. Loopback/private self-bans are refused by
`CmdBan`.
**Residual design risk.** nftables cannot require a completed handshake to
ban; the durable fix is to move auto-ban decisions to userspace on
`ct state established` (conntrack event subscription). Tracked below as a
follow-up.
**Test.** `nft -c -f -`; with a spoofed source hitting `:3389`, confirm no
element appears in `@banned` for the victim within the meter window.

### 3. Split-brain ban state — ⚠️ MITIGATED
**Root cause.** `BanTable::Add` was never called; each reload deleted the
table and re-synced from an empty set, wiping CLI bans; `MirrorToXdp` deleted
XDP auto-bans absent from the userspace set; TTLs were dropped.
**Fix.** `SyncXdp` is now **additive only** with an explicit TTL and never
deletes XDP-only entries; `SyncBanSet` flushes then re-adds with per-element
`timeout`; `BanTable` gained `kMaxEntries` eviction (soonest-expiring first) to
bound spoof-flood memory; `unban`/`nft-flush` clear both tiers.
**Residual.** A durable on-disk ban store in `state_dir` and a single
authoritative source are still recommended (follow-up). Reload still rebuilds
the table, so a full-transaction swap is desirable (see item 18).
**Test.** `femboi-firewall ban 198.51.100.9 600`; `systemctl reload`; confirm
the ban survives (`femboi-firewall list`) and XDP `list-blocked` shows it.

### 4. `established` ahead of meters/DPI — ✅ FIXED
**Root cause.** `ct state established,related accept` sat before the per-port
meters and the nfqueue `queue` rules, so established UDP floods bypassed A2S
meters and TCP payload never reached DPI.
**Fix.** Established/related accept now sits at the end of the input chain,
after all per-port meters and DPI queue hooks.
**Test.** `nft -c -f -`; on a VM, a sustained established-UDP flood on a game
port must show rising `m_<port>_udp` drop counters.

### 5. Geo/DC drops before established — ✅ FIXED
**Root cause.** Geo/datacenter drops ran before conntrack, so replies to the
server's own outbound connections (apt mirrors in Hetzner/OVH/DO ranges) were
dropped.
**Fix.** Geo/DC matches are now `ct state new` only and live in the input
chain (after conntrack); the prerouting chain keeps only pure-L3 ban drops.
**Test.** From the host, `curl` an OVH-hosted URL while `datacenter_filter=1`;
the reply must not be dropped.

### 6. IPv6 — ⚠️ HANDLED
**Root cause.** Rules used `ip saddr` (v4) but the table is `inet`, so IPv6
bypassed protections and ICMPv6 (NDP/RA) fell through to the final `drop`.
**Fix.** Explicit ICMPv6 control accept (ND, RA, packet-too-big) and an
explicit `meta nfproto ipv6 counter accept "ipv6-unmanaged"` so v6 is not
blackholed. nftables `ip saddr` matches are additionally guarded with
`meta nfproto ipv4` where a ban set is consulted.
**Residual.** Full IPv6 enforcement (v6 ban/geo sets) is a follow-up; today v6
is passed, not filtered.
**Test.** `ping6` a neighbor; `ip -6 neigh` must resolve (NDP not dropped).

### 7. XDP not driven by config — ⚠️ FIXED
**Root cause.** The daemon never wrote `fw_cfg`; `per_ip_pps`, `ban_seconds`,
`auto_ban`, `enabled` had no effect on XDP.
**Fix.** `SyncXdp` writes `fw_config` (enabled, pps/syn/udp/icmp budgets,
window, ban time, flags) and mirrors port classes; `enabled=0` disables XDP.
**Test.** `femboi-firewall-xdp config --show` after a daemon reload must reflect
`per_ip_pps`/`ban_seconds`.

### 8. Per-CPU sizing — ✅ FIXED
**Root cause.** `ReadStats` used `get_nprocs_conf()` (configured CPUs) to size
the PERCPU buffer; when `possible > configured` the kernel wrote past the
buffer (heap overflow).
**Fix.** `possible_cpus()` parses `/sys/devices/system/cpu/possible`.
**Test.** Boot with `maxcpus=` < possible; `femboi-firewall-xdp stats` then run
under ASan must not fault.

### 9. LRU/per-CPU rates design — ⏸️ DEFERRED
`rates` is `LRU_PERCPU_HASH` (limit effectively × CPUs, and LRU interleaves
limits) and `blacklist` is LRU (spoof floods can evict real bans). Correct
design: non-LRU `HASH` for `blacklist`, and a total (non-per-CPU) counter or a
deliberate per-CPU sum for `rates`. Deferred because it needs verifier
re-testing and a migration plan for existing pins; documented so it is not
forgotten.

### 10. XDP datapath — ⚠️ PARTIAL
Fixed: `tot_len` vs real frame length check; TCP `doff` and UDP `len`
validation; `ban->hits` via `__sync_fetch_and_add`; `DROP_COUNT` macro
parameter renamed (`pkt_bytes`) to stop shadowing the field; `window_ns == 0`
guarded (limits no longer silently disabled); unprotected/system early-returns
now `count_pass`; ICMP type-3/code-4 (PMTUD) explicitly passed.
**Still open:** VLAN/QinQ parsing (currently `XDP_PASS`), non-TCP/UDP protocols
using `port_class[0]`, `drop_system_port` remains unused, per-port limits not
enforced in XDP, CGNAT fairness for host-wide bans. These require larger design
work and a verifier loop; left for a follow-up PR.

### 11. XDP egress — ✅ REMOVED
`xdp_fw_egress` was meaningless (XDP has no egress hook) and `--egress` merely
re-loaded the first program. Program removed, CLI `--egress` removed; comment
points to TC egress if needed.

### 12. xdpctl detach / pin-dir / reboot — ✅ FIXED
`cmd_detach` now unpins every object in the pin dir (fixes `EEXIST` on
re-attach), `--pin-dir` is honored for load and attach, `/sys/fs/bpf` `mkdir`
removed (systemd mounts bpffs), and the native→generic downgrade prints an
explicit warning. Reboot persistence is addressed by the unit's `ExecStartPre`
(see item 38).

### 18. FlushAll / SyncBanSet / Set* — ✅ FIXED
`destroy table` → `delete table` + ENOENT tolerance (Debian 11/12). `SyncBanSet`
flushes via a device command then adds in 2047-element chunks with per-element
`timeout`. The three near-identical `Set*` helpers are refactored to one
`fill_range_set()` with fail-closed error logging on flush failure.

---

## B. Config / daemon / CLI

### 13. README/config mismatch — ✅ FIXED
`README.md` and `firewall.conf.example` now use the real flat schema; unknown
keys are logged (`ParseKeyValue` else-branch). INI sections remain unsupported
and are documented as such.

### 14. Config parse/save — ✅ FIXED
Slot lines no longer reinitialise the table on every line (only the first);
`Save` writes the full slot table (type/attack/rate/speed/proto) + `whitelist`,
supports non-existent destinations (resolves the parent dir), `fsync`s, and
`chmod 0600`s the temp file. `Save` round-trip is unit-tested.

### 15. Reload correctness — ⚠️ PARTIAL
Reload now uses the `-c` path (not the hardcoded default), re-reads GeoIP and
the datacenter CIDR list, and the disabled state stays resident and honors
SIGHUP. DPI thread lifecycle across reload and the `st.cfg = fresh` vs DPI
reader data race are **still open** — the right fix is a
`shared_ptr<const Config>` snapshot handed to `RunDpiLoop`. Deferred to the
follow-up to avoid introducing an unverifiable lifetime change.

### 16. Status/list/geo/ban — ⚠️ PARTIAL
`CmdStatus` derives `engine` from real table presence; license remnants
(`licensed`, `mode`) removed. Ban counting/listing now uses `nft -j`.
`CmdBan` rejects zero/negative durations (explicit `permanent`) and refuses
local/loopback/multicast targets; `CmdUnban` clears XDP too.
**Still open:** `CmdGeo` reload trigger, atomic rules-file write, escaping,
and wiring `CountryRule.max_pps/max_conns/block_udp` into nft (currently the
geo rate limit is a fixed 150/s).

### 17. Dead settings — ⚠️ PARTIAL
`cti_enabled` removed (Config + `CmdSet`); the README's "threat intelligence"
claim should be dropped. `PortSlot.attack` and several `Counters` fields remain
declared-but-unused; `ban_seconds` now feeds both nft element timeouts and XDP
`ban_time_ns`. Remaining dead fields are flagged for the follow-up.

### 19. `EnsureTcLatency` — ✅ REMOVED
It shelled out to `tc` (not allowlisted, contradicting the no-shell design) on
a hardcoded `ens192` with an unbuilt class hierarchy, silently adding latency
to players. Removed entirely.

### 20. Runtime sysctl writes — ✅ FIXED
The daemon no longer writes `/proc/sys` on every apply. It emits an idempotent
`/etc/sysctl.d/90-femboi.conf` (also shipped by the `.deb`), and `rp_filter` is
deliberately **excluded** to avoid breaking WireGuard/Tailscale/Docker.

### 21. Shutdown lifecycle — ✅ DECIDED
Policy: the ruleset is **retained** on clean exit and crash for continuity;
teardown happens only on explicit `nft-flush` or package removal
(`debian/*.prerm`). Documented in-code and in the unit.

---

## C. DPI

### 22. `DpiAvailable` link error — ✅ FIXED
`DpiAvailable()` is now defined in the `HAVE_NFQUEUE` branch (previously only in
the stub), fixing the `--with-dpi` undefined-reference.

### 23. nfqueue robustness — ⚠️ PARTIAL
Removed legacy `nfq_unbind_pf`/`nfq_bind_pf` (global state; could disrupt other
nfqueue users), added `NFQA_CFG_F_FAIL_OPEN` (guard-compiled) to avoid
self-DoS on queue overflow, and replaced blocking `recv()` with `poll(500ms)`
so `stop` is observed promptly. **Still open:** multi-queue/fanout, and tying
DPI drops into the ban table.

### 24. Split-packet offsets — ✅ FIXED (VERIFIED)
Confirmed against the maintained `gamedig` reference implementation: the
modern format is `-2`, uid(4 bytes), **byte 8 = total count, byte 9 = current
index**, then 2 size bytes. The code had them reversed, so legitimate packet #0
was classified `PKT_EXPLOIT`. Swapped; a zero total is now `PKT_INVALID` (not
exploit). The over-broad `disconnect` scan and the `rcon` prefix block were
removed from the connectionless path.

### 25. L7 HTTP heuristics — ⏸️ DEFERRED
The substring list is still scanned over the first 512 bytes (including
headers), can false-positive on legit apps, applies a NUL check to every TCP
segment (breaks uploads/WebSocket/gRPC), and does ~48k comparisons/packet. The
fix (Aho–Corasick over the request line only; drop the blanket NUL check;
multi-segment handling) is a focused rewrite deferred to its own change.

---

## D. Helpers

### 26. `run_argv` — ✅ FIXED
Pipes are `pipe2(O_CLOEXEC)`; the child is resolved to an absolute path inside
a trusted directory (so `/tmp/nft` is rejected); a minimal env is passed;
stdout and stderr are captured separately and drained with `poll()` so a large
child output cannot deadlock; a 10s deadline SIGTERM/SIGKILLs a hung child.

### 27. util/engine — ⚠️ PARTIAL
`BanTable::Add` sets `manual` on an existing permanent record; `Snapshot` sorts
the full active set before truncating; eviction added. **Still open:** logging
(reopening the file per line, `g_log_level` not atomic, no rate-limit), the
hand-rolled SHA-256 (should use OpenSSL/libsodium with vectors), `MachineHwid`
stability, and the 3× `sort_and_merge` duplication.

### 28. xdp_maps — ⚠️ PARTIAL
`obj_get` sets `FD_CLOEXEC`; `possible_cpus()` fixes per-CPU sizing. **Still
open:** clearing `port_class` for ports removed from config, LRU race in
`ListBlocked`, and making the program pin path configurable.

---

## E. GUI

### 29, 30 — ✅ FIXED
A daemon control socket (`/run/femboi/ctl.sock`, `fw_ctl.hpp/.cpp`) with
`SO_PEERCRED` authorization (uid 0 or the daemon uid), mode 0660, no TCP
listener, now backs `status`/`stats`/`list`/`ban`/`unban`/`set`. Both GUIs route
enforcement through it; the C++ panel dropped its direct `nft`/`conntrack`
shell-outs, and the Python panel no longer calls the pre-rename binary. See
Update 3.

---

## F. Build / CI / repo

### 31. `derle.sh` — ✅ FIXED
Now installs the systemd unit and builds/installs the CO-RE XDP object; adds
`--werror`/`CXX_WERROR`; the empty-array expansions under `set -u` are guarded;
the README clone URL (`FLUXXFALCON`) already matched `origin`, so that sub-item
was ❌ not a defect. Note: binaries still land in `bin/` while the XDP Makefile
uses `linux/bin/` — callers were made consistent (`linux/bin/femboi_xdp.o`).

### 32. Repo hygiene — ⚠️ PARTIAL
Added `tools/geoip/README.md` documenting provenance/license/regeneration and a
`debian/copyright` stanza for `geoip.dat`. Vendored GLFW/ImGui pinning and a
`--version` string remain open.

### 33. CI — ✅ ADDED
`.github/workflows/ci.yml`: Debian 11/12/13 matrix, `--werror` build, unit
tests, `nft -c -f` validation of the generated ruleset (new `ruleset`
subcommand), ASan/UBSan run, shellcheck, GUI build, and an XDP verifier-load
job.

### 34. `.deb` packaging — ✅ ADDED
`debian/` with `control` (Depends: nftables, iproute2, bpftool, libnetfilter-
queue1, conntrack), `rules`, `changelog`, `copyright`, `postinst`, `prerm`,
plus `deploy/femboi-firewall.service` and `deploy/femboi-firewall.logrotate`.

---

## G. Debian-specific

### 36. Debian versions — ⚠️ PARTIAL
`destroy table` removed (item 18) fixes Debian 12; `xdpctl` no longer `mkdir`s
`/sys/fs/bpf`. Distributing a prebuilt CO-RE object and the `linux-headers`
name variance remain deployment concerns (item 39/32).

### 35, 37, 38, 39 — PARTIAL / DEFERRED
- 37 ✅ Hardcoded `ens192` gone with `EnsureTcLatency`; `xdpctl default_iface`
  already derives the default route. Config-selectable interface is a follow-up.
- 38 ⚠️ Reboot persistence via the unit's `ExecStartPre` attach; map state is
  not yet restored from `state_dir`.
- 35 ⏸️ `nftables.service` `flush ruleset` conflict, and hook-priority testing
  vs `iptables-nft`/Docker/ufw/fail2ban, need a live host — documented, not run.
- 39 ⏸️ Update timers, AppArmor profile, and `--version` are follow-ups.

---

## Update 2 — deferred items now implemented

A second pass implemented the highest-value deferred items. **Same caveat: no
compiler/kernel here, so all of this is static-review only and must be verified
by CI/live testing.**

- **Item 15 / DPI reload race — DONE.** `EngineState::cfg` is now
  `std::shared_ptr<const Config>`. Reload builds a new snapshot off to the side
  and publishes it only after it parses. The DPI worker takes its own
  `shared_ptr<const Config>`; on reload the old worker is joined (releasing its
  reference) and a fresh one is started, so `dpi_enabled`/`dpi_queue` toggles
  take effect and the reader can never race a freed config. `RunDpiLoop`
  signature changed accordingly.
- **Item 3 — durable ban store, single source of truth.** `BanTable` gained
  `SetStorePath`/`Persist`/`Restore` (atomic temp+rename, tab-separated). The
  daemon restores `state_dir/bans.db` on start, persists on every mutation and
  sweep, and the CLI `ban`/`unban` write through the same store so userspace is
  authoritative across processes. A unit test covers the round-trip.
- **Item 2 — userspace handshake-gated auto-ban.** New opt-in module
  `linux/src/conntrack.cpp` (`--with-conntrack`, `HAVE_CONNTRACK`) subscribes to
  kernel conntrack events and escalates a source only once conntrack reaches
  `ESTABLISHED`. A spoofed SYN can no longer blackhole a victim; a real abuser
  opening many handshakes still gets banned. Falls back to a stub otherwise.
- **Item 9 / 10 — XDP map redesign.** `blacklist` is now a non-LRU `HASH`
  (spoof floods can no longer evict real bans); `rates` is now a single shared
  `LRU_HASH` (a true per-source total, not multiplied by CPU count); the
  datapath walks up to two 802.1Q/802.1ad tags; non-TCP/UDP protocols and
  non-first fragments are treated as protected instead of bypassing limits; and
  per-port PPS budgets are enforced in XDP via new `port_limits`/`port_rates`
  maps populated from config (`SetPortLimit`).

**Unverified / residual risk:** the conntrack module (libnetfilter-conntrack API
usage, event loop) and the redesigned XDP datapath (verifier acceptance, new
maps) are the least-verified changes here. The `.deb`/CI now build with
`--with-conntrack`; the XDP verifier-load CI job is the gate for the map changes.

## Follow-ups (recommended order)
1. Userspace auto-ban on `ct state established` + durable ban store in
   `state_dir` (items 2, 3, 15).
2. `shared_ptr<const Config>` snapshot for the DPI thread; DPI thread
   lifecycle on reload (item 15).
3. XDP map redesign: non-LRU blacklist, total `rates`, VLAN/L4-port coverage,
   per-port limits (items 9, 10).
4. L7 rewrite: Aho–Corasick on the request line; drop the blanket NUL check
   (item 25).
5. Daemon control socket for the GUI + Python GUI rename (items 29, 30).
6. Geo: wire per-country limits; atomic rules write; reload trigger (item 16).
7. Logging + SHA-256 via OpenSSL (item 27).

---

## Update 3 — fortress pass (IPv6, control socket, L7, egress, geoverify)

A third pass closed the remaining critical gaps. **Still static-review only — no
compiler/kernel in this environment; CI and a live host are the gates.**

- **IPv4-only bans, unfiltered IPv6 (critical) — FIXED.** New `ipv6_enabled`
  config (default **0** = deny). In the default-deny mode the input chain drops
  all IPv6 except loopback, essential ICMPv6 (ND/RA/PMTUD) and
  established/related flows — the previous `ipv6-unmanaged` accept is gone.
  `ipv6_enabled=1` applies v6 sanitisation + a per-source v6 PPS meter and an
  ICMPv6 flood meter, accepting v6 only after the family-agnostic
  sanitisation. XDP mirrors this with `FW_FLAG_IPV6_DENY` and a `drop_ipv6`
  counter (`handle_ipv6`). A `whitelist6` set (populated from `whitelist=`
  v6/CIDR entries) bypasses both.
- **GUI ↔ daemon control socket + rename (items 29, 30) — FIXED.** `fw_ctl`
  (see item 29/30 above). CLI gains `control <request...>`. `gui/fw-gui` and
  `linux/gui/fw_gui.cpp` now use the socket for status/stats/list/ban/unban/set
  and drop the `conntrack` shell-outs; remaining `fluxxfw`/`Fluxx` strings
  and the `/usr/share/fluxxfw` GeoIP path are renamed. A unit test covers
  control-line dispatch.
- **L7 Aho–Corasick (item 25) — FIXED.** Case-insensitive Aho–Corasick over
  the signature set replaces the O(len×patterns) substring scan; one linear
  pass, non-ASCII bytes reset state. Covered by a unit test.
- **Egress A2S amplification — MITIGATED.** Output chain caps outbound UDP to
  the protected game ports globally (`egress_udp_pps`, default 4000) and drops
  replies with no tracked request (`ct state untracked`).
- **XDP attach rollback — ADDED.** `femboi-firewall-xdp attach --rollback-secs N`
  arms a watchdog that detaches after N seconds unless `attach-confirm` runs,
  so a datapath that blacks out access reverts on its own.
- **GeoIP integrity — ADDED.** `tools/geoip/update.sh` downloads over HTTPS,
  requires the `.sha256` sidecar, optionally verifies a GPG signature, and
  installs atomically. The daemon refuses a dataset that does not match a
  present `.sha256` (`LoadGeoVerified`).
- **systemd/deb.** Unit gains `RuntimeDirectory=femboi`; `postinst` creates the
  `femboi` group for socket access.

**Residual / unverified:** the new XDP IPv6 path, the v6 nftables block, the
control-socket server, and the L7 automaton have not been compiled here. CI
(`build+test`, `nft -c -f`, XDP verifier) is the gate. IPv6 bans/geo remain
IPv4-only (documented); `ipv6_enabled=1` is rate-limit/sanitise, not per-IP v6
ban storage. The GUI's `cti_enabled` toggle is a no-op (unknown key).
