package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHealthzHandler(t *testing.T) {
	startTime := time.Now().Add(-2 * time.Hour)
	traps := []string{"ssh", "http", "rdp"}
	handler := healthzHandler("1.2.3", startTime, traps)

	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Fatalf("expected application/json, got %q", ct)
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if resp["status"] != "ok" {
		t.Errorf("expected status=ok, got %v", resp["status"])
	}
	if resp["version"] != "1.2.3" {
		t.Errorf("expected version=1.2.3, got %v", resp["version"])
	}
	if resp["uptime"] == nil || resp["uptime"] == "" {
		t.Error("expected non-empty uptime")
	}

	trapList, ok := resp["traps"].([]any)
	if !ok {
		t.Fatalf("expected traps array, got %T", resp["traps"])
	}
	if len(trapList) != 3 {
		t.Errorf("expected 3 traps, got %d", len(trapList))
	}
}

func TestHealthcheck_Healthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	addr := srv.Listener.Addr().String()
	code := doHealthcheck(addr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
}

func TestHealthcheck_Unhealthy_ConnectionRefused(t *testing.T) {
	code := doHealthcheck("localhost:1")
	if code != 1 {
		t.Fatalf("expected exit 1, got %d", code)
	}
}

func TestHealthcheck_Unhealthy_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	addr := srv.Listener.Addr().String()
	code := doHealthcheck(addr)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d", code)
	}
}

func TestHealthAddr(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{":9550", "localhost:9550"},
		{"0.0.0.0:9550", "0.0.0.0:9550"},
		{"127.0.0.1:9550", "127.0.0.1:9550"},
	}
	for _, tt := range tests {
		got := healthAddr(tt.input)
		if got != tt.want {
			t.Errorf("healthAddr(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
