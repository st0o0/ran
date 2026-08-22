package trap

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

func esTestConfig(t *testing.T) (*config.Config, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := &config.Config{
		Addrs:          map[string]string{"elasticsearch": addr},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}
	return cfg, addr
}

func startES(t *testing.T) string {
	t.Helper()
	cfg, addr := esTestConfig(t)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewElasticsearch(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go func() { _ = trap.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)
	return addr
}

func TestElasticsearchRoot(t *testing.T) {
	addr := startES(t)

	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if resp.Header.Get("X-elastic-product") != "Elasticsearch" {
		t.Error("missing X-elastic-product header")
	}
	if resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", resp.Header.Get("Content-Type"))
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if result["tagline"] != "You Know, for Search" {
		t.Errorf("tagline = %v, want 'You Know, for Search'", result["tagline"])
	}
	if result["cluster_name"] != "elasticsearch" {
		t.Errorf("cluster_name = %v, want 'elasticsearch'", result["cluster_name"])
	}
}

func TestElasticsearchClusterHealth(t *testing.T) {
	addr := startES(t)

	resp, err := http.Get("http://" + addr + "/_cluster/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if result["status"] != "green" {
		t.Errorf("status = %v, want 'green'", result["status"])
	}
}

func TestElasticsearchSearch(t *testing.T) {
	addr := startES(t)

	resp, err := http.Post("http://"+addr+"/_search", "application/json", strings.NewReader(`{"query":{"match_all":{}}}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 401 {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	errObj, ok := result["error"].(map[string]any)
	if !ok {
		t.Fatal("expected error object in response")
	}
	if _, ok := errObj["root_cause"]; !ok {
		t.Error("expected root_cause in error")
	}
}

func TestElasticsearchPut(t *testing.T) {
	addr := startES(t)

	req, _ := http.NewRequest(http.MethodPut, "http://"+addr+"/my-index", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 401 {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if resp.Header.Get("X-elastic-product") != "Elasticsearch" {
		t.Error("missing X-elastic-product header")
	}
}

func TestElasticsearchDelete(t *testing.T) {
	addr := startES(t)

	req, _ := http.NewRequest(http.MethodDelete, "http://"+addr+"/my-index", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 401 {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}
