package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ── Upload Handler (no ClamAV required) ─────────────────────────────────────

func TestUploadHandler_MethodNotAllowed(t *testing.T) {
	// The handler should reject anything that isn't POST.
	handler := uploadHandler(nil) // nil blocklist is fine — we won't reach the scan path

	req := httptest.NewRequest(http.MethodGet, "/upload?name=test.txt", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /upload: got status %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestUploadHandler_Unauthorized(t *testing.T) {
	// When UPLOAD_TOKEN is set, requests without the header should be rejected.
	t.Setenv("UPLOAD_TOKEN", "secret-token-123")
	handler := uploadHandler(nil)

	req := httptest.NewRequest(http.MethodPost, "/upload?name=test.txt", strings.NewReader("data"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("POST /upload without token: got status %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestUploadHandler_WrongToken(t *testing.T) {
	t.Setenv("UPLOAD_TOKEN", "correct-token")
	handler := uploadHandler(nil)

	req := httptest.NewRequest(http.MethodPost, "/upload?name=test.txt", strings.NewReader("data"))
	req.Header.Set("X-Upload-Token", "wrong-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("POST /upload with wrong token: got status %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// ── Filename Sanitisation ───────────────────────────────────────────────────

func TestBadCharsRegex(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"normal.txt", "normal.txt"},
		{"../../etc/passwd", "______etc_passwd"},
		{"file with spaces.doc", "file_with_spaces.doc"},
		{"<script>alert(1)</script>.js", "_script_alert_1___script_.js"},
		{"safe-file_v2.tar.gz", "safe-file_v2.tar.gz"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := badChars.ReplaceAllString(tt.input, "_")
			if got != tt.want {
				t.Errorf("sanitise(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
