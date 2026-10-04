# 🛡️ eBPF XDP Firewall

A high-performance, kernel-level network firewall built with **eBPF/XDP** (eXpress Data Path) that provides real-time packet inspection, automated threat intelligence ingestion, anti-DDoS rate limiting, ClamAV antivirus scanning, and full observability through Prometheus and Grafana.

> **Drop malicious packets before they ever reach the kernel networking stack.**

---

## ✨ Features

- **⚡ XDP-Level Packet Processing** — Operates at the earliest point in the Linux networking stack for maximum throughput and minimum latency
- **🔍 Deep Packet Inspection** — Parses Ethernet, IPv4, TCP, and UDP headers with full protocol awareness and payload signature matching
- **🧠 Live Threat Intelligence** — Automatically fetches and injects malicious IP blocklists from the [IPsum](https://github.com/stamparm/ipsum) threat feed (15,000+ IPs from 30+ sources)
- **🚦 Anti-DDoS Rate Limiter** — Per-IP sliding-window rate limiter in kernel space drops floods exceeding 20,000 packets/second
- **🧩 IP Fragment Handling** — Tracks and blocks fragmented packets using an LRU hash map, preventing evasion via IP fragmentation
- **🦠 ClamAV Antivirus Gateway** — HTTP upload endpoint that streams files through ClamAV for real-time malware scanning, with optional auto-ban of infected uploaders
- **📊 Prometheus Metrics** — Exports real-time telemetry including passed/dropped/rate-limited packet counts, active threat signatures, and file scan statistics
- **📈 Grafana Dashboards** — Pre-provisioned dashboard with auto-configured Prometheus datasource — ready on first boot
- **⚙️ Production Systemd Service** — Runs as a proper system service with auto-restart, environment-based secrets, and lifecycle hooks
- **☁️ One-Command Azure Deployment** — Fully automated provisioning, build, and deployment via `deploy-azure.sh`

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│              AZURE CLOUD (Virtual Machine)               │
│              Ubuntu 22.04 · Standard_B1s                 │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌───────────────────────────────────────────────────┐  │
│  │           XDP eBPF PROGRAM (Kernel Space)         │  │
│  │               kernel/xdp_telemetry.c              │  │
│  │                                                   │  │
│  │  ┌──────────┐  ┌────────────┐  ┌──────────────┐  │  │
│  │  │ Parse    │─▶│ Blocklist  │─▶│ Rate Limiter │  │  │
│  │  │ Headers  │  │ Lookup     │  │ (20k pps)    │  │  │
│  │  └──────────┘  └─────┬──────┘  └──────┬───────┘  │  │
│  │                      │                 │          │  │
│  │             ┌────────▼───────┐ ┌───────▼───────┐  │  │
│  │             │   XDP_DROP    │ │ Fragment      │  │  │
│  │             │  (Blocked)   │ │ Cache (LRU)   │  │  │
│  │             └──────────────┘ └───────────────┘  │  │
│  │                                                   │  │
│  │             ┌──────────────┐  ┌───────────────┐  │  │
│  │             │  XDP_PASS    │  │ Per-CPU       │  │  │
│  │             │ (Allowed)   │  │ Counters      │  │  │
│  │             └──────────────┘  └───────────────┘  │  │
│  └───────────────────────────────────────────────────┘  │
│                           │                             │
│  ┌───────────────────────▼───────────────────────────┐  │
│  │          CONTROL PLANE (User Space · Go)          │  │
│  │                  main.go + scanner.go             │  │
│  │                                                   │  │
│  │  ┌────────────┐ ┌──────────┐ ┌────────────────┐  │  │
│  │  │ Threat     │ │ ClamAV   │ │ Prometheus     │  │  │
│  │  │ Intel      │ │ Upload   │ │ Metrics        │  │  │
│  │  │ Ingestion  │ │ Gateway  │ │ /metrics       │  │  │
│  │  │ (IPsum)    │ │ :8000    │ │ :8080          │  │  │
│  │  └────────────┘ └──────────┘ └──────┬─────────┘  │  │
│  └─────────────────────────────────────┼─────────────┘  │
│                                        │                │
│  ┌─────────────────────────────────────▼─────────────┐  │
│  │           OBSERVABILITY (Docker Compose)          │  │
│  │     Prometheus (:9090) + Grafana (:3000)          │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
ebpf-firewall/
├── kernel/
│   └── xdp_telemetry.c          # eBPF XDP kernel program (C)
├── main.go                       # Go control plane
├── scanner.go                    # ClamAV antivirus upload gateway
├── main_test.go                  # Unit tests (IP conversion, env helpers)
├── scanner_test.go               # Scanner tests (auth, sanitisation)
├── grafana/
│   ├── dashboards/
│   │   └── ebpf-shield.json     # Pre-built Grafana dashboard
│   └── provisioning/
│       ├── dashboards/
│       │   └── dashboards.yml   # Dashboard auto-provisioning
│       └── datasources/
│           └── prometheus.yml   # Prometheus datasource config
├── scripts/
│   ├── vm-setup.sh              # One-command VM setup (packages → systemd → observability)
│   └── allow-my-ip.sh           # Restrict Azure NSG to your current IP
├── deploy-azure.sh              # Full Azure deployment automation
├── docker-compose.yml           # Prometheus + Grafana stack
├── prometheus.yml               # Prometheus scrape configuration
├── Makefile                     # Build automation (bpf, build, test, clean)
├── .env.example                 # Environment variable reference
├── go.mod / go.sum              # Go module dependencies
├── threat.dat                   # Local threat data cache
└── LICENSE                      # MIT License
```

---

## 🔧 Prerequisites

- **Linux** with kernel ≥ 5.15 (eBPF & XDP support required)
- **Go** ≥ 1.25
- **Clang/LLVM** (for compiling eBPF C programs)
- **libbpf** development headers
- **Docker & Docker Compose** (for the observability stack)
- **ClamAV** (for the antivirus upload gateway)
- **Root privileges** (required for loading eBPF programs and attaching XDP hooks)

### Install Dependencies (Ubuntu/Debian)

```bash
# Build tools + ClamAV
sudo apt update
sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r) \
  docker.io docker-compose-v2 clamav-daemon

# Go (if not installed)
sudo snap install go --classic
```

Or use the automated setup script:
```bash
sudo bash scripts/vm-setup.sh
```

---

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/AakashGs10/ebpf-firewall.git
cd ebpf-firewall
```

### 2. Build Everything

```bash
make          # Compiles eBPF bytecode + Go binary
```

Or step by step:
```bash
make bpf      # Compile kernel/xdp_telemetry.c → kernel/xdp_telemetry.o
make build    # Build Go binary → ./shield
```

### 3. Configure Environment

```bash
cp .env.example .env
# Edit .env to set GRAFANA_PASSWORD and other options
```

### 4. Start the Observability Stack

```bash
docker compose up -d
```

This launches:
- **Prometheus** on port `9090`
- **Grafana** on port `3000` (with pre-provisioned dashboard)

### 5. Run the Firewall

```bash
sudo ./shield
```

Or directly with Go:
```bash
sudo go run main.go scanner.go
```

The control plane will:
1. Load the compiled eBPF program into the kernel
2. Attach the XDP hook to your network interface
3. Start the threat intelligence feed ingestion loop
4. Launch the ClamAV antivirus upload gateway on `:8000`
5. Expose Prometheus metrics on `:8080/metrics`
6. Expose a health check on `:8080/healthz`

### 6. Run Tests

```bash
make test
```

---

## ☁️ Cloud Deployment (Azure)

### Automated Deployment

Deploy the entire stack to an Azure VM with a single command:

```bash
bash deploy-azure.sh
```

This will:
1. Authenticate with Azure (`az login`)
2. Create a Resource Group + Ubuntu 22.04 VM (Free Tier)
3. Configure NSG rules (ports 22, 3000, 8000, 8080, 9090)
4. SSH into the VM and run `scripts/vm-setup.sh` which:
   - Installs all dependencies (Clang, Go, Docker, ClamAV)
   - Compiles the eBPF program natively on the VM
   - Creates a systemd service (`ebpf-shield.service`)
   - Starts Prometheus + Grafana via Docker Compose
5. Print access URLs for Grafana, Prometheus, and metrics

### Manual VM Setup

If you already have an Ubuntu VM:
```bash
git clone https://github.com/AakashGs10/ebpf-firewall.git
cd ebpf-firewall
sudo bash scripts/vm-setup.sh
```

### Restrict Access to Your IP

```bash
bash scripts/allow-my-ip.sh
```

---

## 📊 Metrics & Observability

### Prometheus Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `ebpf_packets_passed_total` | Counter | IPv4 packets allowed through by XDP |
| `ebpf_packets_dropped_total` | Counter | Packets dropped by XDP (all reasons) |
| `ebpf_packets_ratelimited_total` | Counter | Packets dropped by the per-IP rate limiter |
| `ebpf_active_threat_signatures` | Gauge | Malicious IPs in the kernel blocklist |
| `ebpf_files_scanned_total` | Counter | Files scanned by the upload gateway |
| `ebpf_files_blocked_total` | Counter | Infected files rejected |

### Access Dashboards

- **Grafana**: [http://localhost:3000](http://localhost:3000) (password from `.env`)
- **Prometheus**: [http://localhost:9090](http://localhost:9090)
- **Raw Metrics**: [http://localhost:8080/metrics](http://localhost:8080/metrics)
- **Health Check**: [http://localhost:8080/healthz](http://localhost:8080/healthz)

---

## 🧠 How It Works

### Kernel Space (eBPF/XDP)

The XDP program (`kernel/xdp_telemetry.c`) runs at the **NIC driver level** and performs:

1. **Header Parsing** — Validates and extracts Ethernet → IPv4 → TCP/UDP headers
2. **Blocklist Lookup** — Checks source IPs against a kernel-space hash map (`BPF_MAP_TYPE_HASH`) populated with known malicious IPs
3. **Rate Limiting** — Per-IP sliding window counter using an LRU map; drops packets exceeding 20,000 pps
4. **Fragment Blocking** — Uses an LRU hash map to track fragmented packet flows, blocking subsequent fragments
5. **Payload Inspection** — Checks first 4 bytes of TCP/UDP payload for known attack signatures
6. **Per-CPU Counters** — Lockless counters for dropped, rate-limited, and passed packets
7. **Verdict** — Returns `XDP_DROP` for blocked traffic or `XDP_PASS` for clean traffic

### User Space (Go Control Plane)

The Go application (`main.go` + `scanner.go`) handles:

1. **eBPF Lifecycle** — Loads the compiled eBPF object, attaches the XDP hook, manages map references
2. **Threat Intelligence** — Periodically fetches the [IPsum](https://github.com/stamparm/ipsum) blocklist and injects up to 15,000 malicious IPs into the kernel hash map
3. **ClamAV Gateway** — Accepts file uploads via HTTP POST, streams them through ClamAV's INSTREAM protocol, and optionally bans uploaders of infected files
4. **Metrics Export** — Reads per-CPU counters and exposes Prometheus metrics for external scraping

---

## 🦠 ClamAV Antivirus Gateway

The upload gateway (`scanner.go`) provides a secure file upload endpoint:

```bash
# Upload a file for scanning
curl -X POST -H "X-Upload-Token: $TOKEN" \
  --data-binary @suspicious_file.exe \
  "http://localhost:8000/upload?name=suspicious_file.exe"

# Response for clean file:
# CLEAN: file accepted (stream: OK)

# Response for infected file:
# BLOCKED: stream: Eicar-Signature FOUND
```

**Features:**
- Streams files directly to ClamAV (no disk write before scan)
- 4 concurrent scan slots with backpressure (HTTP 429)
- 20 MB file size limit
- Token-based authentication (`UPLOAD_TOKEN` env var)
- Optional auto-ban: set `BAN_ON_INFECTED=1` to add the uploader's IP to the kernel blocklist
- Filename sanitisation (path traversal protection)

---

## ⚙️ eBPF Maps

| Map | Type | Max Entries | Purpose |
|-----|------|-------------|---------|
| `blocklist` | `BPF_MAP_TYPE_HASH` | 20,000 | Store blocked IP addresses |
| `fragment_cache` | `BPF_MAP_TYPE_LRU_HASH` | 5,000 | Track fragmented flows from threats |
| `rate_map` | `BPF_MAP_TYPE_LRU_HASH` | 65,536 | Per-IP packet rate state |
| `counters` | `BPF_MAP_TYPE_PERCPU_ARRAY` | 3 | Lockless drop/ratelimit/pass counters |

---

## 🛡️ Threat Intelligence

The firewall automatically fetches live threat data from the [IPsum](https://github.com/stamparm/ipsum) project — a curated, daily-updated list of suspicious and malicious IP addresses sourced from 30+ threat intelligence feeds.

- **Feed URL**: `https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt`
- **Update Interval**: Every 6 hours
- **Max Entries**: 15,000 IPs per refresh cycle
- **Injection**: IPs are written directly into the kernel `blocklist` hash map

---

## 🔐 Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `IFACE` | `eth0` | Network interface to attach XDP to |
| `METRICS_ADDR` | `:8080` | Prometheus metrics listen address |
| `XDP_MODE` | `generic` | XDP attach mode (`generic` or `native`) |
| `UPLOAD_TOKEN` | *(empty)* | Auth token for the upload gateway |
| `BAN_ON_INFECTED` | `0` | Auto-ban IPs that upload malware (`1` to enable) |
| `TEST_BLOCK_IP` | *(empty)* | Block a specific IP at startup (testing) |
| `GRAFANA_PASSWORD` | *(required)* | Grafana admin password (used by Docker Compose) |

---

## 🧰 Tech Stack

| Layer | Technology |
|-------|-----------|
| **Cloud** | Microsoft Azure (VM, NSG, Resource Groups) |
| **OS** | Ubuntu 22.04 LTS |
| **Data Plane** | C, eBPF/XDP |
| **Control Plane** | Go, cilium/ebpf |
| **Antivirus** | ClamAV (clamd INSTREAM protocol) |
| **Metrics** | Prometheus (`client_golang`) |
| **Visualization** | Grafana (auto-provisioned) |
| **Orchestration** | Docker Compose, systemd |
| **Threat Feed** | IPsum (stamparm) |

---

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

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
