# femboi-firewall

Linux firewall for game servers (Source Engine, CS2, Rust) combining eBPF/XDP packet filtering, nftables rulesets, and an optional ImGui panel.

## Filtering Layers

- **XDP (eBPF)**: Early packet drops at the driver level before reaching the network stack.
- **nftables**: Rate limiting, dynamic IP bans, GeoIP filtering, and port rules.
- **L7 DPI (nfqueue)**: Inspection for game query floods (A2S_INFO) and malformed payloads.
- **ImGui GUI**: Optional desktop panel to monitor traffic and manage rules.

---

## User Interface

- **Telemetry & Traffic Graphs**: Real-time ingress bandwidth, mitigation rates, drop stats, and live attack logs.
- **Port Quotas & Protocol Rules**: Per-port bandwidth caps, UDP/TCP protocol separation, and rate limit budgets.
- **Active Ban Management**: Dynamic blacklist decay timers and instant manual unbans.
- **GeoIP Access Policies**: In-memory binary trie country filtering (`geoip.dat`).
- **Engine Settings**: Runtime toggles for XDP datapath, L7 DPI, ASN filters, and burst thresholds.

---

## Architecture Overview

```
 NIC Ingress  ───►  [ Tier 1: XDP / eBPF Driver ]    L3/L4 Wire-Speed Drops
                          │ (XDP_PASS)
                          ▼
                    [ Tier 2: nftables Ruleset ]     Kernel Policy & GeoIP
                          │ (accept)
                          ▼
                    [ Tier 3: nfqueue L7 DPI ]       Game Protocol Verification
                          │ (clean stream)
                          ▼
                    [ Protected Application ]        srcds, cs2, nginx
```

| Ingress Layer | Subsystem | Latency | Main Responsibility |
|:---|:---|:---|:---|
| **Tier 1** | **XDP (eBPF)** | `< 1 µs` | High-volume flood drops before Linux network stack allocation. |
| **Tier 2** | **nftables** | Low | Stateful rate limits, per-port bandwidth budgets, ASN and country sets. |
| **Tier 3** | **nfqueue DPI** | Targeted | Steam A2S query validation, challenge enforcement, and exploit payload drops. |

---

## Features

- **XDP Driver Offload**: Drops malicious packets at driver level to prevent CPU exhaustion.
- **Source Engine Protocol Guard**: Validates `A2S_INFO` and challenge responses to mitigate reflection amplification.
- **Embedded GeoIP**: In-memory binary search over 200,000+ IP CIDRs (`geoip.dat`).
- **Datacenter / ASN Filter**: Rejects automated traffic originating from hosting and cloud IP ranges.
- **ImGui Desktop Control Panel**: Hardware-accelerated desktop interface for real-time monitoring and rule editing.
- **Zero Runtime Overhead**: Written in pure C++20 / C. No Python, Node.js, or Java runtime requirements.
- **Live Rule Reload**: Modify limits and unban addresses on-the-fly without dropping active connections.

---

## Installation & Quickstart

### 1. Install Dependencies (Debian / Ubuntu)

```bash
sudo apt update
sudo apt install -y build-essential nftables clang llvm libbpf-dev bpftool \
                    libgl1-mesa-dev libglfw3-dev libx11-dev linux-headers-$(uname -r)
```

### 2. Build & Install Daemon

```bash
git clone https://github.com/FLUXXFALCON/femboi-firewall.git
cd femboi-firewall

chmod +x derle.sh
./derle.sh
sudo ./derle.sh --install
```

### 3. Build Operator GUI (Optional)

```bash
make -C linux/gui
sudo cp linux/gui/fw-gui /usr/local/bin/fluxxfw-gui
```

### 4. Service Control

```bash
# Start and enable daemon
sudo systemctl enable --now femboi-firewall

# Check status
sudo systemctl status femboi-firewall
```

---

## Configuration Example

Configuration file: `/etc/femboi/firewall.conf`

```ini
[firewall]
enabled=1
interface=eth0
per_ip_pps=1000
burst_pps=2000
ban_duration_secs=3600

enable_xdp=1
enable_dpi=1
enable_geoip=1
enable_datacenter_filter=1
enable_autoban=1

[ports]
27015 = udp:game:100:100
27016 = udp:game:100:100
443   = tcp:web:50:25
80    = tcp:web:50:25
```

Reload ruleset without dropping active traffic:
```bash
sudo systemctl reload femboi-firewall
```

---

## CLI Management

```bash
# View daemon status and packet counters
femboi-firewall --status

# Inspect XDP eBPF map statistics
femboi-firewall-xdp stats

# View active nftables ruleset
sudo nft list table inet femboifw
```

---

## Windows Cross-Compilation

To cross-compile static Linux binaries from Windows:

```cmd
:: Requires zig in PATH
derle.bat
```

Output binaries are written to `bin/` (`femboi-firewall`, `femboi-firewall-xdp`).

---

## License

Distributed under the [MIT License](LICENSE).
