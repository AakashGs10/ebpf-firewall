package main

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	clamdSocket = "/var/run/clamav/clamd.ctl"
	uploadDir   = "./uploads"
	maxUpload   = 20 << 20 // 20 MB
)

var (
	filesScannedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ebpf_files_scanned_total",
		Help: "Total files scanned by the upload gateway",
	})
	filesBlockedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ebpf_files_blocked_total",
		Help: "Total infected files rejected by the upload gateway",
	})
	scanSlots = make(chan struct{}, 4) // max 4 concurrent scans
	badChars  = regexp.MustCompile(`[^A-Za-z0-9._-]`)
)

func scanStream(r io.Reader) (string, error) {
	conn, err := net.DialTimeout("unix", clamdSocket, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(90 * time.Second))

	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return "", err
	}

	buf := make([]byte, 32*1024)
	lenBuf := make([]byte, 4)
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			binary.BigEndian.PutUint32(lenBuf, uint32(n))
			if _, err := conn.Write(lenBuf); err != nil {
				return "", err
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return "", err
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return "", rerr
		}
	}
	if _, err := conn.Write([]byte{0, 0, 0, 0}); err != nil {
		return "", err
	}

	resp, err := io.ReadAll(conn)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(resp), "\x00\n "), nil
}

func uploadHandler(blocklist *ebpf.Map) http.HandlerFunc {
	token := os.Getenv("UPLOAD_TOKEN")
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "use POST", http.StatusMethodNotAllowed)
			return
		}
		if token != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Upload-Token")), []byte(token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		select {
		case scanSlots <- struct{}{}:
			defer func() { <-scanSlots }()
		default:
			http.Error(w, "scanner busy, retry shortly", http.StatusTooManyRequests)
			return
		}

		name := badChars.ReplaceAllString(filepath.Base(r.URL.Query().Get("name")), "_")
		if strings.Trim(name, "._") == "" {
			name = fmt.Sprintf("upload-%d", time.Now().Unix())
		}

		tmp, err := os.CreateTemp(uploadDir, "quarantine-*")
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		tmpPath := tmp.Name()
		keep := false
		defer func() {
			if !keep {
				os.Remove(tmpPath)
			}
		}()

		body := http.MaxBytesReader(w, r.Body, maxUpload)
		verdict, err := scanStream(io.TeeReader(body, tmp))
		tmp.Close()

		if err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				http.Error(w, "file too large (max 20 MB)", http.StatusRequestEntityTooLarge)
				return
			}
			log.Printf("[SCANNER] scan error: %v", err)
			http.Error(w, "scan failed, file rejected", http.StatusServiceUnavailable)
			return
		}

		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)

		switch {
		case strings.HasSuffix(verdict, "FOUND"):
			filesScannedTotal.Inc()
			filesBlockedTotal.Inc()
			log.Printf("[SCANNER] BLOCKED %s from %s -> %s", name, clientIP, verdict)

			if os.Getenv("BAN_ON_INFECTED") == "1" {
				ip := IPtoUint32(clientIP)
				val := uint32(1)
				if ip == 0 {
					log.Printf("[SCANNER] cannot ban %q (not IPv4)", clientIP)
				} else if err := blocklist.Put(&ip, &val); err != nil {
					log.Printf("[SCANNER] ban FAILED for %s: %v", clientIP, err)
				} else {
					log.Printf("[SCANNER] %s added to kernel blocklist", clientIP)
				}
			}
			http.Error(w, "BLOCKED: "+verdict+"\n", http.StatusForbidden)

		case strings.HasSuffix(verdict, "OK"):
			filesScannedTotal.Inc()
			final := filepath.Join(uploadDir, fmt.Sprintf("%d-%s", time.Now().Unix(), name))
			if err := os.Rename(tmpPath, final); err != nil {
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			}
			keep = true
			log.Printf("[SCANNER] CLEAN %s from %s", name, clientIP)
			fmt.Fprintf(w, "CLEAN: file accepted (%s)\n", verdict)

		default:
			log.Printf("[SCANNER] unexpected clamd reply %q, rejecting %s", verdict, name)
			http.Error(w, "scan inconclusive, file rejected", http.StatusServiceUnavailable)
		}
	}
}

func startUploadGateway(blocklist *ebpf.Map) {
	if err := os.MkdirAll(uploadDir, 0o750); err != nil {
		log.Printf("[SCANNER] cannot create upload dir: %v", err)
		return
	}
	if os.Getenv("UPLOAD_TOKEN") == "" {
		log.Println("[SCANNER] WARNING: UPLOAD_TOKEN not set, uploads are unauthenticated")
	}
	http.HandleFunc("/upload", uploadHandler(blocklist))
	log.Println("[SCANNER] Upload gateway registered on :8080/upload")
}
