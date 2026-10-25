package trap

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

// fakeLAPI records logins and alert pushes. The first alert push is answered
// with 401 to force a re-login.
type fakeLAPI struct {
	mu       sync.Mutex
	logins   int
	pushes   int
	tokens   []string // Authorization header of every push
	accepted [][]map[string]any
}

func (f *fakeLAPI) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/watchers/login", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.logins++
		token := fmt.Sprintf("token-%d", f.logins)
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token":  token,
			"expire": time.Now().Add(time.Hour).Format(time.RFC3339),
		})
	})
	mux.HandleFunc("/v1/alerts", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.pushes++
		f.tokens = append(f.tokens, r.Header.Get("Authorization"))
		if f.pushes == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var batch []map[string]any
		if err := json.Unmarshal(body, &batch); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.accepted = append(f.accepted, batch)
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

func (f *fakeLAPI) acceptedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, b := range f.accepted {
		n += len(b)
	}
	return n
}

// TestEndToEndTrapToCrowdSec runs a real trap with a real Sensor and the real
// CrowdSec sink against a fake LAPI. The peer address is set with a PROXY
// header, because loopback is never reported.
func TestEndToEndTrapToCrowdSec(t *testing.T) {
	lapi := &fakeLAPI{}
	srv := httptest.NewServer(lapi.handler())
	defer srv.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := metrics.New(prometheus.NewRegistry(), "test")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sink, err := alert.NewCrowdSec(ctx, alert.CrowdSecConfig{
		URL:           srv.URL,
		MachineID:     "ran",
		Password:      "secret",
		BatchInterval: 100 * time.Millisecond,
		BatchSize:     2,
	}, logger, m)
	if err != nil {
		t.Fatal(err)
	}
	sensor := alert.NewSensor(alert.SensorConfig{SummaryWindow: time.Hour}, sink, logger)
	defer sensor.Close()

	cfg := &config.Config{
		Addrs:          map[string]string{"telnet": "127.0.0.1:0"},
		PerProto:       make(map[string]config.ProtoConfig),
		ProxyProtocol:  true,
		ProxyTrusted:   loopbackPrefixes,
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
		MaxAuthRetries: 1,
	}
	tr := NewTelnet(cfg, logger, m, NewLimiter(cfg.MaxSessions, cfg.MaxPerIP), sensor)
	addr := serveTrap(t, ctx, tr)

	ips := []string{"8.8.8.8", "1.1.1.1", "8.8.4.4", "1.0.0.1", "9.9.9.9"}
	for _, ip := range ips {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(conn, "PROXY TCP4 %s 127.0.0.1 40000 23\r\n", ip)
		fmt.Fprint(conn, "root\r\nsecret\r\n")
		_, _ = io.Copy(io.Discard, bufio.NewReader(conn)) // the trap closes after one attempt
		conn.Close()
	}

	waitFor(t, func() bool { return lapi.acceptedCount() == len(ips) })

	lapi.mu.Lock()
	defer lapi.mu.Unlock()

	if lapi.logins < 2 {
		t.Errorf("logins = %d, want >= 2 (initial login and re-login after 401)", lapi.logins)
	}
	if len(lapi.tokens) < 2 || lapi.tokens[0] == lapi.tokens[1] {
		t.Errorf("push tokens = %v, want a fresh token on the retry after 401", lapi.tokens)
	}
	if len(lapi.accepted) < 3 {
		t.Errorf("accepted %d batches, want >= 3 for 5 alerts at batch size 2", len(lapi.accepted))
	}

	seen := map[string]bool{}
	for _, batch := range lapi.accepted {
		if len(batch) > 2 {
			t.Errorf("batch of %d alerts exceeds batch size 2", len(batch))
		}
		for _, a := range batch {
			checkCrowdSecAlert(t, a, seen)
		}
	}
	for _, ip := range ips {
		if !seen[ip] {
			t.Errorf("no alert received for %s", ip)
		}
	}
}

func checkCrowdSecAlert(t *testing.T, a map[string]any, seen map[string]bool) {
	t.Helper()
	if a["scenario"] != "custom/ran-telnet-trap" {
		t.Errorf("scenario = %v, want custom/ran-telnet-trap", a["scenario"])
	}
	if a["remediation"] != true {
		t.Errorf("remediation = %v, want true", a["remediation"])
	}
	if d, ok := a["decisions"].([]any); !ok || len(d) != 0 {
		t.Errorf("decisions = %v, want an empty array", a["decisions"])
	}
	src, _ := a["source"].(map[string]any)
	value, _ := src["value"].(string)
	if value == "" || src["ip"] != value {
		t.Errorf("source value/ip = %v/%v, want the same non-empty address", src["value"], src["ip"])
	}
	seen[value] = true

	events, _ := a["events"].([]any)
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	ev, _ := events[0].(map[string]any)
	meta := map[string]string{}
	rawMeta, _ := ev["meta"].([]any)
	for _, kv := range rawMeta {
		p, _ := kv.(map[string]any)
		k, _ := p["key"].(string)
		v, _ := p["value"].(string)
		meta[k] = v
	}
	if meta["class"] != "attack" {
		t.Errorf("event meta class = %q, want attack", meta["class"])
	}
	if _, ok := meta["password"]; ok {
		t.Error("password must never reach CrowdSec")
	}
}
