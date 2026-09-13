<p align="center">
  <h1 align="center">🛡️ Femboi Firewall</h1>
  <p align="center">
    <strong>High-Performance Multi-Layer DDoS Mitigation Engine & ImGui Desktop Control Panel for Linux</strong>
  </p>
  <p align="center">
    <a href="https://github.com/FLUXXFALCON/femboi-firewall/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge" alt="MIT License"></a>
    <img src="https://img.shields.io/badge/Kernel-Linux%205.x%20%7C%206.x-orange.svg?style=for-the-badge&logo=linux&logoColor=white" alt="Linux Kernel">
    <img src="https://img.shields.io/badge/Datapath-eBPF%20%2F%20XDP-red.svg?style=for-the-badge" alt="eBPF / XDP">
    <img src="https://img.shields.io/badge/Firewall-nftables-purple.svg?style=for-the-badge" alt="nftables">
    <img src="https://img.shields.io/badge/GUI-Dear%20ImGui%20%2B%20OpenGL-green.svg?style=for-the-badge" alt="Dear ImGui">
    <img src="https://img.shields.io/badge/Language-C%2B%2B20%20%7C%20C-00599C.svg?style=for-the-badge&logo=cplusplus" alt="C++20">
  </p>
</p>

---

## ⚡ Overview

**Femboi Firewall** is an enterprise-grade, multi-layer DDoS defense system designed specifically for high-throughput Linux game servers (Source Engine, CS2, Rust) and web services. 

It combines the raw speed of **XDP (eBPF)** at driver level with the surgical precision of **nftables** stateful policy sets, user-space **L7 Deep Packet Inspection (DPI)**, and an ultra-low latency **Dear ImGui** desktop administration panel.

---

## 📸 Interface Showcase

<div align="center">

### 📊 Real-Time Telemetry & Attack Inspector
*Monitor ingress, mitigated pps, and active bans with live graph analytics.*
<br><br>
<img src="assets/overview.png" alt="Femboi Firewall Overview" width="900" style="border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.5);" />

<br><br>

### 🎮 Port Budgets & Game Protocol Profiles
*Configure per-port bandwidth quotas, protocol filters (UDP/TCP), and anti-amplification rules.*
<br><br>
<img src="assets/ports.png" alt="Ports Configuration" width="900" style="border-radius: 8px;" />

<br><br>

### 🚫 Real-Time Ban Enforcer & Dynamic Blacklists
*Automated temporary bans with customizable decay timers, instant manual unbans, and CIDR management.*
<br><br>
<img src="assets/bans.png" alt="Bans Management" width="900" style="border-radius: 8px;" />

<br><br>

### 🌍 GeoIP Country Filtering
*Hardware-accelerated binary trie GeoIP filtering with zero-overhead country whitelists/blacklists.*
<br><br>
<img src="assets/geo.png" alt="GeoIP Rules" width="900" style="border-radius: 8px;" />

<br><br>

### ⚙️ Engine Settings & Datapath Modulators
*One-click switches for XDP wire-speed offload, L7 DPI, ASN datacenter filters, and PPS burst limits.*
<br><br>
<img src="assets/settings.png" alt="Settings Panel" width="900" style="border-radius: 8px;" />

</div>

---

## 🏛️ Multi-Tier Architecture

Femboi Firewall operates across three distinct security domains to drop malicious traffic at the earliest possible stage:

```
                            ┌──────────────────────────────────────────────┐
  100GbE / 10GbE NIC ────►  │ Layer 1: XDP / eBPF Kernel Driver Program   │  Wire Speed
                            │  • Hardware/driver drop before sk_buff       │  L3 + L4
                            │  • SYN/UDP/ICMP flood mitigation             │  Zero Alloc
                            │  • Per-IP token-bucket rate limiter          │
                            └──────────────────────┬───────────────────────┘
                                                   │ XDP_PASS
                            ┌──────────────────────▼───────────────────────┐
                            │ Layer 2: nftables (`inet femboifw`)          │  Kernel Policy
                            │  • Dynamic IP & ASN ban sets                 │  Stateful L4
                            │  • GeoIP fast-lookup rules                   │
                            │  • Per-port PPS and bandwidth rate limits    │
                            └──────────────────────┬───────────────────────┘
                                                   │ accept
                            ┌──────────────────────▼───────────────────────┐
                            │ Layer 3: nfqueue L7 Deep Packet Inspection   │  Userspace
                            │  • Source Engine (A2S) query flood filter    │  Application L7
                            │  • Exploit & malformed payload rejection     │
                            │  • HTTP/TLS scanner & botnet signatures      │
                            └──────────────────────┬───────────────────────┘
                                                   │ Clean Traffic
                            ┌──────────────────────▼───────────────────────┐
                            │ Protected Game Server / Web Application      │
                            │ (srcds, CS2, Nginx, Flask)                   │
                            └──────────────────────────────────────────────┘
```

| Tier | Component | Datapath | Overhead | Role |
|:---:|:---:|:---:|:---:|:---|
| **Tier 1** | **XDP / eBPF** | Network Driver Hook | **< 1 µs** | Drops volumetric floods before memory allocation in the Linux kernel stack. |
| **Tier 2** | **nftables** | Kernel Netfilter | **Low** | Manages dynamic ban sets, datacenter ASN blacklists, and port rate budgets. |
| **Tier 3** | **L7 DPI** | Userspace `nfnetlink_queue` | **Targeted** | Inspects game payload headers to discard reflection attacks and buffer overflow exploits. |

---

## ✨ Features

- **🚀 Wire-Speed XDP Offload**: Drops millions of packets per second (`Mpps`) directly at the network interface card.
- **🛡️ Source Engine Exploit Protection**: Deep packet inspection for Steam / Source query protocols (A2S_INFO, A2S_PLAYER challenge enforcement).
- **🌐 Fast GeoIP Engine**: Memory-mapped binary search over 200,000+ IP ranges (`geoip.dat`) with microsecond lookup times.
- **🏢 Datacenter / Cloud Proxy Filter**: Blocks automated botnets and malicious proxies hosted on popular cloud providers.
- **🖥️ Hardware-Accelerated ImGui Panel**: Real-time cyberpunk HUD built with Dear ImGui, GLFW, and modern OpenGL.
- **📦 Zero External Runtimes**: Compiled as standalone native C++ ELF binaries. No Python, Node.js, or Java dependencies required.
- **⚙️ Dynamic Live Reload**: Modify rules, unban IPs, and toggle modules on-the-fly without service interruption or connection drops.

---

## 🚀 Quick Start (Linux / Debian / Ubuntu)

### 1. Prerequisites

Install the standard compilation toolchain and kernel headers:

```bash
sudo apt update
sudo apt install -y build-essential nftables clang llvm libbpf-dev bpftool \
                    libgl1-mesa-dev libglfw3-dev libx11-dev linux-headers-$(uname -r)
```

### 2. Clone & Build

```bash
git clone https://github.com/FLUXXFALCON/femboi-firewall.git
cd femboi-firewall

# Compile the core firewall daemon and XDP control tools
chmod +x derle.sh
./derle.sh

# Install binaries to /usr/local/bin and configure systemd service
sudo ./derle.sh --install
```

### 3. Compile the Desktop Control Panel (Optional)

If running an X11 desktop environment or remote VNC/X forwarding:

```bash
make -C linux/gui
sudo cp linux/gui/fw-gui /usr/local/bin/fluxxfw-gui
```

### 4. Start the Protection Service

```bash
# Enable and launch the systemd daemon
sudo systemctl enable --now femboi-firewall

# Verify active status
sudo systemctl status femboi-firewall
```

---

## ⚙️ Configuration (`/etc/femboi/firewall.conf`)

Femboi Firewall uses an intuitive INI-style configuration file located at `/etc/femboi/firewall.conf`:

```ini
[firewall]
# Master protection switch (1 = active, 0 = disabled)
enabled=1

# Network interface for XDP attachment
interface=eth0

# Rate limiting thresholds
per_ip_pps=1000
burst_pps=2000
ban_duration_secs=3600

# Protection modules
enable_xdp=1
enable_dpi=1
enable_geoip=1
enable_datacenter_filter=1
enable_autoban=1

# Port definitions (Port : Protocol : RateLimit % : MaxMbps)
[ports]
27015 = udp:game:100:100
27016 = udp:game:100:100
443   = tcp:web:50:25
80    = tcp:web:50:25
```

Apply updates instantly:
```bash
sudo systemctl reload femboi-firewall
```

---

## 🛠️ CLI Utilities

The engine provides dedicated command-line utilities for terminal inspection:

```bash
# Display live engine status, active ban count, and packet counters
femboi-firewall --status

# Inspect XDP eBPF datapath statistics
femboi-firewall-xdp stats

# Inspect nftables kernel ruleset
sudo nft list table inet femboifw
```

---

## 🪟 Windows Cross-Compilation

To cross-compile the static Linux binaries directly on Windows without installing a Linux VM:

1. Ensure [Zig](https://ziglang.org/) is installed and added to `PATH`.
2. Run the Windows builder script:
   ```cmd
   derle.bat
   ```
3. The statically linked ELF binaries will be produced in the `bin/` directory.

---

## 📜 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

Developed with ❤️ by **FLUXXFALCON**.
