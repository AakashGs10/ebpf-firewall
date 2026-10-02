package main

import (
	"bufio"
	"bytes"
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
	"github.com/cilium/ebpf/ringbuf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// PacketEvent must exactly match the C struct memory layout
type PacketEvent struct {
	SrcIP      uint32
	DstIP      uint32
	SrcPort    uint16
	DstPort    uint16
	Protocol   uint8
	_          uint8 // Padding for memory alignment
	PacketSize uint16
}

var (
	packetsPassedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ebpf_packets_passed_total",
		Help: "Total number of packets passed through the eBPF kernel program",
	})
	packetsDroppedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ebpf_packets_dropped_total",
		Help: "Total number of packets dropped by the eBPF kernel program",
	})
	activeThreatSignatures = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ebpf_active_threat_signatures",
		Help: "Number of malicious IPs currently injected into the kernel blocklist",
	})
)

// IPtoUint32 safely converts an IPv4 string to the exact byte order the Linux kernel expects
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

// Autonomous worker to fetch live threat intelligence
func ingestThreatIntelligence(blocklist *ebpf.Map) {
	feedURL := "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"

	for {
		log.Println("[INTELLIGENCE] Fetching live threat feed from IPsum...")
		resp, err := http.Get(feedURL)
		if err != nil {
			log.Printf("Warning: Failed to reach threat feed: %v\n", err)
			time.Sleep(60 * time.Second)
			continue
		}

		scanner := bufio.NewScanner(resp.Body)
		count := 0
		maxEntries := 10000

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			parts := strings.Fields(line)
			if len(parts) > 0 {
				ipStr := parts[0]
				ipUint := IPtoUint32(ipStr)
				if ipUint != 0 {
					val := uint32(1)
					blocklist.Put(&ipUint, &val)
					count++
					if count >= maxEntries {
						break
					}
				}
			}
		}
		resp.Body.Close()

		log.Printf("[INTELLIGENCE] Successfully injected %d active threat signatures into the kernel.\n", count)
		activeThreatSignatures.Set(float64(count))

		time.Sleep(60 * time.Second)
	}
}

// pollDropMetrics reads the PERCPU_ARRAY map from the kernel and aggregates
// drop counts across all CPU cores into a single Prometheus counter.
func pollDropMetrics(dropMetricsMap *ebpf.Map) {
	var key uint32 = 0
	var lastTotal uint64 = 0

	for {
		var perCPUValues []uint64
		err := dropMetricsMap.Lookup(&key, &perCPUValues)
		if err == nil {
			var currentTotal uint64 = 0
			for _, val := range perCPUValues {
				currentTotal += val
			}

			if currentTotal > lastTotal {
				delta := currentTotal - lastTotal
				packetsDroppedTotal.Add(float64(delta))
				lastTotal = currentTotal
			}
		}
		time.Sleep(1 * time.Second)
	}
}

func main() {
	ifaceName := "eth0"
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Fatal: Failed to find interface %s: %v\n", ifaceName, err)
	}

	// Load the compiled eBPF object file
	spec, err := ebpf.LoadCollectionSpec("./kernel/xdp_telemetry.o")
	if err != nil {
		log.Fatalf("Fatal: Failed to load eBPF object file: %v\n", err)
	}

	objs := struct {
		ExtractNetworkTelemetry *ebpf.Program `ebpf:"extract_network_telemetry"`
		Blocklist               *ebpf.Map     `ebpf:"blocklist"`
		Ringbuf                 *ebpf.Map     `ebpf:"ringbuf"`
		DropMetrics             *ebpf.Map     `ebpf:"drop_metrics"`
	}{}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("Fatal: Failed to load eBPF objects into kernel: %v\n", err)
	}
	defer objs.ExtractNetworkTelemetry.Close()
	defer objs.Blocklist.Close()
	defer objs.Ringbuf.Close()
	defer objs.DropMetrics.Close()

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.ExtractNetworkTelemetry,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Fatal: Failed to attach XDP program to interface: %v\n", err)
	}
	defer l.Close()
	log.Printf("[SYSTEM] eBPF Firewall actively deployed on interface: %s\n", ifaceName)

	go ingestThreatIntelligence(objs.Blocklist)
	go pollDropMetrics(objs.DropMetrics)

	go func() {
		http.Handle("/metrics", promhttp.Handler())
		log.Println("[TELEMETRY] Prometheus exporter listening on :8080/metrics")
		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Fatalf("Fatal: Prometheus HTTP server crashed: %v", err)
		}
	}()

	rd, err := ringbuf.NewReader(objs.Ringbuf)
	if err != nil {
		log.Fatalf("Fatal: Failed to open ring buffer: %v", err)
	}
	defer rd.Close()

	go func() {
		var event PacketEvent
		for {
			record, err := rd.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				continue
			}

			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				continue
			}
			packetsPassedTotal.Inc()
		}
	}()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper
	log.Println("[SYSTEM] Received shutdown signal. Detaching eBPF program and halting infrastructure...")
}