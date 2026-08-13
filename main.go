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

type PacketEvent struct {
	SrcIP      uint32
	DstIP      uint32
	SrcPort    uint16
	DstPort    uint16
	Protocol   uint8
	_          uint8
	PacketSize uint16
}

var (
	packetsPassedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ebpf_packets_passed_total",
		Help: "Total number of packets passed through the eBPF kernel program",
	})
	activeThreatSignatures = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ebpf_active_threat_signatures",
		Help: "Number of malicious IPs currently injected into the kernel blocklist",
	})
)

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

func main() {
	ifaceName := "lo"
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Fatal: Failed to find interface %s: %v\n", ifaceName, err)
	}

	// Updated relative path pointing to the kernel folder
	spec, err := ebpf.LoadCollectionSpec("../kernel/xdp_telemetry.o")
	if err != nil {
		log.Fatalf("Fatal: Failed to load eBPF object file: %v\n", err)
	}

	objs := struct {
		ExtractNetworkTelemetry *ebpf.Program `ebpf:"extract_network_telemetry"`
		Blocklist               *ebpf.Map     `ebpf:"blocklist"`
		Ringbuf                 *ebpf.Map     `ebpf:"ringbuf"`
	}{}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("Fatal: Failed to load eBPF objects into kernel: %v\n", err)
	}
	defer objs.ExtractNetworkTelemetry.Close()
	defer objs.Blocklist.Close()
	defer objs.Ringbuf.Close()

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
	log.Println("[SYSTEM] Received shutdown signal. Detaching eBPF program and halting...")
}