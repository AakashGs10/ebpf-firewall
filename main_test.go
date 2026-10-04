package main

import (
	"net"
	"testing"
)

// ── IPtoUint32 ──────────────────────────────────────────────────────────────

func TestIPtoUint32_ValidIPv4(t *testing.T) {
	tests := []struct {
		input string
		want  uint32
	}{
		{"1.2.3.4", 0x04030201},     // Little-endian: bytes reversed
		{"127.0.0.1", 0x0100007f},   // Loopback
		{"0.0.0.0", 0x00000000},     // All zeros
		{"255.255.255.255", 0xffffffff}, // Broadcast
		{"10.0.0.1", 0x0100000a},    // Private range
		{"192.168.1.1", 0x0101a8c0}, // Common LAN
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := IPtoUint32(tt.input)
			if got != tt.want {
				t.Errorf("IPtoUint32(%q) = 0x%08x, want 0x%08x", tt.input, got, tt.want)
			}
		})
	}
}

func TestIPtoUint32_Invalid(t *testing.T) {
	invalids := []string{
		"",
		"not-an-ip",
		"999.999.999.999",
		"::1",           // IPv6 loopback (no IPv4 representation)
		"2001:db8::1",   // IPv6
	}
	for _, s := range invalids {
		t.Run(s, func(t *testing.T) {
			got := IPtoUint32(s)
			if got != 0 {
				t.Errorf("IPtoUint32(%q) = 0x%08x, want 0", s, got)
			}
		})
	}
}

func TestIPtoUint32_RoundTrip(t *testing.T) {
	// Convert to uint32 and back to make sure no data is lost.
	original := "203.0.113.42"
	u := IPtoUint32(original)
	if u == 0 {
		t.Fatalf("IPtoUint32(%q) returned 0", original)
	}
	// Reconstruct IP from the uint32 (little-endian bytes)
	b := make([]byte, 4)
	b[0] = byte(u)
	b[1] = byte(u >> 8)
	b[2] = byte(u >> 16)
	b[3] = byte(u >> 24)
	got := net.IP(b).String()
	if got != original {
		t.Errorf("round-trip: got %s, want %s", got, original)
	}
}

// ── getenv ──────────────────────────────────────────────────────────────────

func TestGetenv_Default(t *testing.T) {
	// A key that definitely does not exist
	got := getenv("EBPF_TEST_NONEXISTENT_KEY_12345", "fallback")
	if got != "fallback" {
		t.Errorf("getenv returned %q, want %q", got, "fallback")
	}
}

func TestGetenv_Set(t *testing.T) {
	t.Setenv("EBPF_TEST_KEY", "custom_value")
	got := getenv("EBPF_TEST_KEY", "fallback")
	if got != "custom_value" {
		t.Errorf("getenv returned %q, want %q", got, "custom_value")
	}
}
