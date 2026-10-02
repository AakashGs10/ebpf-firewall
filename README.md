# 🛡️ eBPF XDP Firewall

A high-performance, kernel-level network firewall built with **eBPF/XDP** (eXpress Data Path) that provides real-time packet inspection, automated threat intelligence ingestion, and full observability through Prometheus and Grafana.

> **Drop malicious packets before they ever reach the kernel networking stack.**

---

## ✨ Features

- **⚡ XDP-Level Packet Processing** — Operates at the earliest point in the Linux networking stack for maximum throughput and minimum latency
- **🔍 Deep Packet Inspection** — Parses Ethernet, IPv4, TCP, and UDP headers with full protocol awareness
- **🧠 Live Threat Intelligence** — Automatically fetches and injects malicious IP blocklists from the [IPsum](https://github.com/stamparm/ipsum) threat feed
- **🧩 IP Fragment Handling** — Tracks and blocks fragmented packets from known threats using an LRU hash map, preventing evasion via IP fragmentation
- **📊 Prometheus Metrics** — Exports real-time telemetry including packet counts and active threat signatures
- **📈 Grafana Dashboards** — Full observability stack with pre-configured Docker Compose setup
- **🔄 Ring Buffer Telemetry** — Streams per-packet metadata (src/dst IP, ports, protocol, size) from kernel to userspace via eBPF ring buffer

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      NETWORK INTERFACE                  │
│                         (NIC)                           │
└─────────────────────┬───────────────────────────────────┘
                      │ Incoming Packet
                      ▼
┌─────────────────────────────────────────────────────────┐
│              XDP eBPF PROGRAM (Kernel Space)            │
│                 xdp_telemetry.c                         │
│                                                         │
│  ┌──────────┐   ┌────────────┐   ┌──────────────────┐  │
│  │ Parse    │──▶│ Blocklist  │──▶│ Fragment Cache   │  │
│  │ Headers  │   │ Lookup     │   │ (LRU Hash Map)   │  │
│  └──────────┘   └─────┬──────┘   └────────┬─────────┘  │
│                       │                    │            │
│              ┌────────▼────────┐  ┌────────▼─────────┐  │
│              │   XDP_DROP      │  │  Ring Buffer     │  │
│              │  (Blocked IP)   │  │  (Telemetry)     │  │
│              └─────────────────┘  └────────┬─────────┘  │
│                                            │            │
│              ┌─────────────────┐           │            │
│              │   XDP_PASS      │           │            │
│              │ (Clean Traffic) │           │            │
│              └─────────────────┘           │            │
└────────────────────────────────────────────┼────────────┘
                                             │
                      ┌──────────────────────▼────────────┐
                      │     CONTROL PLANE (User Space)    │
                      │          main.go (Go)             │
                      │                                   │
                      │  ┌────────────┐ ┌──────────────┐  │
                      │  │ Threat     │ │ Prometheus   │  │
                      │  │ Intel      │ │ Metrics      │  │
                      │  │ Ingestion  │ │ /metrics     │  │
                      │  └────────────┘ └──────┬───────┘  │
                      └────────────────────────┼──────────┘
                                               │
                      ┌────────────────────────▼──────────┐
                      │        OBSERVABILITY STACK        │
                      │   Prometheus (:9090) + Grafana    │
                      │         (Docker Compose)          │
                      └───────────────────────────────────┘
```

---

## 📁 Project Structure

```
ebpf-firewall/
├── kernel/
│   ├── xdp_telemetry.c      # eBPF XDP kernel program (C)
│   └── xdp_telemetry.o      # Compiled eBPF bytecode
├── control_plane/
│   ├── main.go               # Go control plane application
│   └── xdp_telemetry.o      # eBPF object (loaded by control plane)
├── xdp_telemetry.c           # Root-level eBPF source
├── main.go                   # Root-level control plane entry point
├── Makefile                  # Build automation for eBPF compilation
├── docker-compose.yml        # Prometheus + Grafana stack
├── prometheus.yml            # Prometheus scrape configuration
├── threat.dat                # Local threat data cache
├── go.mod                    # Go module dependencies
└── go.sum                    # Go dependency checksums
```

---

## 🔧 Prerequisites

- **Linux** with kernel ≥ 5.15 (eBPF & XDP support required)
- **Go** ≥ 1.25
- **Clang/LLVM** (for compiling eBPF C programs)
- **libbpf** development headers
- **Docker & Docker Compose** (for the observability stack)
- **Root privileges** (required for loading eBPF programs and attaching XDP hooks)

### Install Dependencies (Ubuntu/Debian)

```bash
# Build tools
sudo apt update
sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r)

# Go (if not installed)
# See https://go.dev/doc/install

# Docker
sudo apt install -y docker.io docker-compose
```

---

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/AakashGs10/ebpf-firewall.git
cd ebpf-firewall
```

### 2. Compile the eBPF Kernel Program

```bash
make
```

This compiles `xdp_telemetry.c` into `xdp_telemetry.o` using Clang with the BPF target:
```bash
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include/$(uname -m)-linux-gnu -c xdp_telemetry.c -o xdp_telemetry.o
```

### 3. Start the Observability Stack

```bash
docker-compose up -d
```

This launches:
- **Prometheus** on port `9090`
- **Grafana** on port `3000`

### 4. Run the Firewall

```bash
sudo go run main.go
```

Or build and run:
```bash
go build -o ebpf-firewall .
sudo ./ebpf-firewall
```

The control plane will:
1. Load the compiled eBPF program into the kernel
2. Attach the XDP hook to your network interface
3. Start the threat intelligence feed ingestion loop
4. Begin streaming packet telemetry from the ring buffer
5. Expose Prometheus metrics on `/metrics`

---

## 📊 Metrics & Observability

### Prometheus Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `ebpf_packets_passed_total` | Counter | Total packets processed by the eBPF program |
| `ebpf_active_threat_signatures` | Gauge | Number of malicious IPs in the kernel blocklist |

### Access Dashboards

- **Prometheus**: [http://localhost:9090](http://localhost:9090)
- **Grafana**: [http://localhost:3000](http://localhost:3000) (default: `admin`/`admin`)

---

## 🧠 How It Works

### Kernel Space (eBPF/XDP)

The XDP program (`xdp_telemetry.c`) runs at the **NIC driver level** and performs:

1. **Header Parsing** — Validates and extracts Ethernet → IPv4 → TCP/UDP headers
2. **Blocklist Lookup** — Checks source IPs against a kernel-space hash map (`BPF_MAP_TYPE_HASH`) populated with known malicious IPs
3. **Fragment Tracking** — Uses an LRU hash map to track fragmented packet flows, blocking subsequent fragments from threats
4. **Telemetry Emission** — Sends packet metadata to userspace via a ring buffer (`BPF_MAP_TYPE_RINGBUF`)
5. **Verdict** — Returns `XDP_DROP` for blocked IPs or `XDP_PASS` for clean traffic

### User Space (Go Control Plane)

The Go application (`main.go`) handles:

1. **eBPF Lifecycle** — Loads the compiled eBPF object, attaches the XDP hook, and manages map references
2. **Threat Intelligence** — Periodically fetches the [IPsum](https://github.com/stamparm/ipsum) blocklist and injects up to 10,000 malicious IPs into the kernel hash map
3. **Telemetry Consumer** — Reads per-packet events from the ring buffer and logs them
4. **Metrics Export** — Exposes Prometheus counters and gauges for external scraping

---

## ⚙️ eBPF Maps

| Map | Type | Max Entries | Purpose |
|-----|------|-------------|---------|
| `ringbuf` | `BPF_MAP_TYPE_RINGBUF` | 256 KB | Stream packet telemetry to userspace |
| `blocklist` | `BPF_MAP_TYPE_HASH` | 10,000 | Store blocked IP addresses |
| `fragment_cache` | `BPF_MAP_TYPE_LRU_HASH` | 5,000 | Track fragmented flows from threats |

---

## 🛡️ Threat Intelligence

The firewall automatically fetches live threat data from the [IPsum](https://github.com/stamparm/ipsum) project — a curated, daily-updated list of suspicious and malicious IP addresses sourced from 30+ threat intelligence feeds.

- **Feed URL**: `https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt`
- **Update Interval**: Periodic (configurable in source)
- **Max Entries**: 10,000 IPs per refresh cycle
- **Injection**: IPs are written directly into the kernel `blocklist` hash map

---

## 🧰 Tech Stack

| Layer | Technology |
|-------|-----------|
| **Data Plane** | C, eBPF/XDP |
| **Control Plane** | Go, cilium/ebpf |
| **Metrics** | Prometheus (`client_golang`) |
| **Visualization** | Grafana |
| **Orchestration** | Docker Compose |
| **Threat Feed** | IPsum (stamparm) |

---

## 📜 License

This project is open source. See the repository for license details.

---

## 🤝 Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 👤 Author

**Aakash G S** — [@AakashGs10](https://github.com/AakashGs10)

---

<p align="center">
  <i>Built with eBPF — because security should happen at the speed of the kernel.</i>
</p>
