package trap

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

func proxyTestConfig(t *testing.T) (*config.Config, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := &config.Config{
		Addrs:          map[string]string{"httpproxy": addr},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}
	return cfg, addr
}

func startProxy(t *testing.T) string {
	t.Helper()
	cfg, addr := proxyTestConfig(t)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewHTTPProxy(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go trap.Start(ctx)
	time.Sleep(100 * time.Millisecond)
	return addr
}

func TestHTTPProxyConnect(t *testing.T) {
	addr := startProxy(t)

	req, _ := http.NewRequest(http.MethodConnect, "http://"+addr, nil)
	req.Host = "example.com:443"
	resp, err := http.DefaultTransport.(*http.Transport).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 407 {
		t.Errorf("status = %d, want 407", resp.StatusCode)
	}
	if resp.Header.Get("Proxy-Authenticate") == "" {
		t.Error("missing Proxy-Authenticate header")
	}
}

func TestHTTPProxyAbsoluteURL(t *testing.T) {
	addr := startProxy(t)

	req, _ := http.NewRequest(http.MethodGet, "http://"+addr, nil)
	req.URL.Host = addr
	req.URL.Path = "/"
	req.RequestURI = "http://example.com/"
	req.Host = "example.com"

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.Write([]byte("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"))

	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	response := string(buf[:n])

	if !contains(response, "407") {
		t.Errorf("expected 407 in response, got: %s", response)
	}
}

func TestHTTPProxyWithAuth(t *testing.T) {
	addr := startProxy(t)

	creds := base64.StdEncoding.EncodeToString([]byte("admin:secret"))

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.Write([]byte("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic " + creds + "\r\n\r\n"))

	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	response := string(buf[:n])

	if !contains(response, "407") {
		t.Errorf("expected 407 in response, got: %s", response)
	}
}

func TestHTTPProxyNonProxyRequest(t *testing.T) {
	addr := startProxy(t)

	resp, err := http.Get("http://" + addr + "/some/path")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	if resp.StatusCode != 400 {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
