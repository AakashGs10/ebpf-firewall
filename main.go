package main

import (
	"bufio"
	"encoding/binary"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	packetsPassedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ebpf_packets_passed_total",
		Help: "IPv4 packets allowed through by the XDP program",
	})
	packetsDroppedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ebpf_packets_dropped_total",
		Help: "Packets dropped by the XDP program (all reasons)",
	})
	packetsRateLimitedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ebpf_packets_ratelimited_total",
		Help: "Packets dropped because a source IP exceeded the per-second rate limit",
	})
	activeThreatSignatures = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ebpf_active_threat_signatures",
		Help: "Malicious IPs loaded into the kernel blocklist from the threat feed",
	})
)

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// IPtoUint32 matches how the XDP program reads ip->saddr on a little-endian CPU.
func IPtoUint32(ipStr string) uint32 {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0
	}
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(ip)
}

func ingestThreatIntelligence(blocklist *ebpf.Map) {
	const feedURL = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
	const maxEntries = 15000 // map holds 20000; the rest is headroom for bans
	client := &http.Client{Timeout: 30 * time.Second}

	for {
		log.Println("[INTELLIGENCE] Fetching live threat feed from IPsum...")
		resp, err := client.Get(feedURL)
		if err != nil {
			log.Printf("[INTELLIGENCE] feed unreachable: %v", err)
			time.Sleep(60 * time.Second)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			log.Printf("[INTELLIGENCE] feed returned HTTP %d", resp.StatusCode)
			time.Sleep(60 * time.Second)
			continue
		}

		sc := bufio.NewScanner(resp.Body)
		count := 0
		for sc.Scan() && count < maxEntries {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.Fields(line)
			ip := IPtoUint32(parts[0])
			if ip == 0 {
				continue
			}
			val := uint32(1)
			if err := blocklist.Put(&ip, &val); err != nil {
				log.Printf("[INTELLIGENCE] map update failed: %v", err)
				break
			}
			count++
		}
		resp.Body.Close()

		log.Printf("[INTELLIGENCE] Injected %d threat signatures into the kernel.", count)
		activeThreatSignatures.Set(float64(count))
		time.Sleep(6 * time.Hour)
	}
}

// pollCounter sums one slot of the per-CPU counters map and feeds the delta to Prometheus.
func pollCounter(m *ebpf.Map, key uint32, c prometheus.Counter) {
	var last uint64
	for {
		var perCPU []uint64
		if err := m.Lookup(&key, &perCPU); err == nil {
			var total uint64
			for _, v := range perCPU {
				total += v
			}
			if total > last {
				c.Add(float64(total - last))
				last = total
			}
		}
		time.Sleep(time.Second)
	}
}

func main() {
	ifaceName := getenv("IFACE", "eth0")
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Fatal: interface %s not found: %v", ifaceName, err)
	}

	spec, err := ebpf.LoadCollectionSpec("./kernel/xdp_telemetry.o")
	if err != nil {
		log.Fatalf("Fatal: cannot load eBPF object: %v", err)
	}

	objs := struct {
		Prog      *ebpf.Program `ebpf:"extract_network_telemetry"`
		Blocklist *ebpf.Map     `ebpf:"blocklist"`
		Counters  *ebpf.Map     `ebpf:"counters"`
	}{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("Fatal: kernel rejected the eBPF program: %v", err)
	}
	defer objs.Prog.Close()
	defer objs.Blocklist.Close()
	defer objs.Counters.Close()

	// Generic (software) XDP works on every cloud NIC, including Azure hv_netvsc.
	var flags link.XDPAttachFlags = link.XDPGenericMode
	if getenv("XDP_MODE", "generic") == "native" {
		flags = 0
	}
	l, err := link.AttachXDP(link.XDPOptions{Program: objs.Prog, Interface: iface.Index, Flags: flags})
	if err != nil {
		log.Fatalf("Fatal: cannot attach XDP to %s: %v", ifaceName, err)
	}
	defer l.Close()
	log.Printf("[SYSTEM] eBPF Firewall actively deployed on interface: %s\n", ifaceName)

	// Test hook, only active when the env var is set (used by the local gate test).
	if tip := os.Getenv("TEST_BLOCK_IP"); tip != "" {
		ip := IPtoUint32(tip)
		val := uint32(1)
		if ip != 0 {
			if err := objs.Blocklist.Put(&ip, &val); err != nil {
				log.Printf("[TEST] cannot blocklist %s: %v", tip, err)
			} else {
				log.Printf("[TEST] blocklisted %s", tip)
			}
		}
	}

	go ingestThreatIntelligence(objs.Blocklist)
	go pollCounter(objs.Counters, 0, packetsDroppedTotal)
	go pollCounter(objs.Counters, 1, packetsRateLimitedTotal)
	go pollCounter(objs.Counters, 2, packetsPassedTotal)
	go startUploadGateway(objs.Blocklist)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	go func() {
		addr := getenv("METRICS_ADDR", ":8080")
		log.Printf("[TELEMETRY] Prometheus exporter listening on %s/metrics", addr)
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Fatalf("Fatal: metrics server crashed: %v", err)
		}
	}()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper
	log.Println("[SYSTEM] Shutdown signal received. Detaching eBPF program.")
}
