# Femboi Firewall — Linux DDoS Engine

An open-source, multi-layer DDoS mitigation engine for Linux game and web servers.

Two build entry points are available:

| Entry point | Runs on | Output |
|---|---|---|
| `derle.bat` | Windows (cross-compiles via zig) | Statically linked Linux ELF binaries |
| `derle.sh`  | Linux / Debian (native g++) | Native ELF binaries |

---

## 1. Architecture

| Layer | Implementation | Description |
|---|---|---|
| L3/L4 Wire Speed | **XDP** (`linux/xdp`) | Drops in driver before skb allocation; hardware/native rate filtering |
| L3/L4 Policy | **nftables** (`linux/src/nft.cpp`) | Dynamic sets, geo/datacenter filters, per-port token buckets |
| L7 Inspection | **nfqueue DPI** (`linux/src/dpi.cpp`) | Optional payload classifier for Source-engine exploits & scanner probes |
| Service Management | **systemd** | Headless standalone daemon with zero external dependencies |

```
                 ┌──────────────────────────────────────────────┐
   NIC ──► XDP   │ femboi_xdp.o    (BPF, driver hook)           │  wire speed
                 │  whitelist / blacklist / per-IP PPS /        │  L3 + L4
                 │  SYN + UDP + ICMP flood, auto-ban            │
                 └───────────────────┬──────────────────────────┘
                                     │ XDP_PASS
                 ┌───────────────────▼──────────────────────────┐
                 │ nftables  `inet femboifw`                    │  netfilter
                 │  ban + geo + datacenter sets, per-port       │  L3/L4 policy
                 │  budgets, management-plane exemptions        │
                 └───────────────────┬──────────────────────────┘
                                     │ accept
                 ┌───────────────────▼──────────────────────────┐
                 │ (optional) nfqueue DPI                       │  userspace
                 │  srcds exploit + HTTP/TLS scanner signatures  │  L7
                 └───────────────────┬──────────────────────────┘
                                     │
                 ┌───────────────────▼──────────────────────────┐
                 │ Protected Application (srcds / nginx)        │
                 └──────────────────────────────────────────────┘
```

---

## 2. Directory Layout

```
firewall/
├── derle.sh                     ← Native Linux build
├── derle.bat                    ← Windows cross-build via portable zig
├── firewall.conf.example        ← Sample configuration (/etc/femboi/firewall.conf)
├── geoip.dat                    ← Country IP range database
├── linux/
│   ├── include/
│   │   ├── fw.hpp               ← Core engine headers and structures
│   │   ├── proc.hpp             ← Subprocess and command execution helpers
│   │   ├── fw_portable.hpp      ← Game protocol and network helpers
│   │   └── fw_l7_http.hpp       ← HTTP and TLS signature analysis
│   ├── src/
│   │   ├── util.cpp             ← IP parsing, SHA-256 and logging
│   │   ├── engine.cpp           ← Config parser, port definitions, GeoIP, ASN
│   │   ├── nft.cpp              ← nftables ruleset and set management
│   │   ├── dpi.cpp              ← Optional L7 deep packet inspection
│   │   └── main.cpp             ← Standalone CLI and enforcement daemon
│   └── xdp/
│       ├── fw_xdp.c             ← BPF kernel program
│       ├── fw_common.h          ← Shared BPF/userspace definitions
│       ├── xdp_maps.hpp         ← Direct syscall map manager
│       ├── xdpctl.cpp           ← CLI utility for XDP operations
│       └── Makefile             ← BPF object build makefile
└── bin/                         ← Build outputs (femboi-firewall, femboi-firewall-xdp)
```

---

## 3. Build and Deployment

### 3a. Build on Windows (Cross-compilation)
`derle.bat` compiles static Linux binaries directly on Windows using zig:

```bat
cd firewall
derle.bat
```
Output: `bin\femboi-firewall` and `bin\femboi-firewall-xdp` (statically linked with musl; zero shared library dependencies).

### 3b. Build on Linux (Native)
```bash
sudo apt install build-essential nftables
cd firewall && ./derle.sh
sudo ./derle.sh --install
```

### 3c. Compile XDP Kernel Program
The BPF program compiles against the running kernel's BTF:
```bash
sudo apt install clang llvm bpftool libbpf-dev linux-headers-$(uname -r)
cd firewall/linux/xdp && make
sudo make install
sudo femboi-firewall-xdp doctor
sudo femboi-firewall-xdp attach --iface eth0
```

---

## 4. Standalone Open-Source Operation

This release operates **100% standalone**:
- **No License Verification:** Daemon starts immediately and runs without activation keys or auth tokens.
- **No Remote Telemetry or Heartbeats:** The firewall never connects to external servers; all state is local and private.
- **No Auto-Updaters:** Binaries and rules are entirely controlled by the system operator.
- **Zero Cloud Failure Points:** Attacks or third-party outages cannot impact local filtering.

---

## 5. CLI Reference

### nftables Engine & Daemon
```bash
femboi-firewall daemon                 # Run enforcement daemon
femboi-firewall apply                  # Install base nftables ruleset
femboi-firewall status                 # View engine status JSON
femboi-firewall ports                  # List protected ports
femboi-firewall list                   # List active IP bans
femboi-firewall ban 1.2.3.4 3600       # Ban IP for seconds (0 = permanent)
femboi-firewall unban 1.2.3.4          # Lift ban
femboi-firewall geo RU block           # Apply country policy
femboi-firewall set auto_ban 1         # Update runtime setting
femboi-firewall doctor                 # Check prerequisites
femboi-firewall nft-flush              # Remove nftables ruleset
```

### XDP Datapath Controller
```bash
femboi-firewall-xdp attach --iface eth0   # Load and attach BPF filter
femboi-firewall-xdp detach --iface eth0   # Detach BPF filter
femboi-firewall-xdp stats --watch         # Real-time PPS and drop rates
femboi-firewall-xdp block 1.2.3.4 3600    # XDP-level driver drop
femboi-firewall-xdp unblock 1.2.3.4       # Remove XDP block
femboi-firewall-xdp allow 10.0.0.5        # Whitelist IP
femboi-firewall-xdp port 27015 game       # Classify port in XDP
femboi-firewall-xdp config --pps 1500     # Adjust rate limit thresholds
```
