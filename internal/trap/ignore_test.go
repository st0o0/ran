package trap

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

func counterVal(t *testing.T, vec *prometheus.CounterVec, labels ...string) float64 {
	t.Helper()
	var out dto.Metric
	if err := vec.WithLabelValues(labels...).Write(&out); err != nil {
		t.Fatal(err)
	}
	return out.GetCounter().GetValue()
}

func gaugeVal(t *testing.T, vec *prometheus.GaugeVec, labels ...string) float64 {
	t.Helper()
	var out dto.Metric
	if err := vec.WithLabelValues(labels...).Write(&out); err != nil {
		t.Fatal(err)
	}
	return out.GetGauge().GetValue()
}

func ignoreTelnetConfig(maxPerIP int, ignore ...string) *config.Config {
	cfg := &config.Config{
		Addrs:          map[string]string{"telnet": "127.0.0.1:0"},
		PerProto:       make(map[string]config.ProtoConfig),
		ProxyProtocol:  true,
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       maxPerIP,
		MaxAuthRetries: 1,
	}
	prefixes, err := config.ParseIgnoreList("RAN_IGNORE_IPS", strings.Join(ignore, ","))
	if err != nil {
		panic(err)
	}
	cfg.IgnoreIPs = prefixes
	return cfg
}

// telnetAttempt sends one login attempt with the given PROXY source and waits
// for the trap to close the connection.
func telnetAttempt(t *testing.T, addr, proxySource string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	family := "TCP4"
	if strings.Contains(proxySource, ":") {
		family = "TCP6"
	}
	fmt.Fprintf(conn, "PROXY %s %s 127.0.0.1 40000 23\r\n", family, proxySource)
	fmt.Fprint(conn, "root\r\nsecret\r\n")
	_, _ = io.Copy(io.Discard, bufio.NewReader(conn))
}

// TestEndToEndIgnoredSourceNeverReachesCrowdSec runs a real trap, a real Sensor
// and the real CrowdSec sink against a fake LAPI: attacks from ignored sources
// (a single address, an IPv4 CIDR, an IPv6 range and a mapped form) push
// nothing, while a neighbor outside the list still alerts. Ignored sessions are
// logged with ignored=true and counted in ran_ignored_sessions_total.
func TestEndToEndIgnoredSourceNeverReachesCrowdSec(t *testing.T) {
	lapi := &fakeLAPI{}
	srv := httptest.NewServer(lapi.handler())
	defer srv.Close()

	logs := &syncBuffer{}
	logger := newJSONLogger(logs)
	m := metrics.New(prometheus.NewRegistry(), "test")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := ignoreTelnetConfig(10, "8.8.8.8", "1.1.1.0/24", "2606:4700:4700::/48")
	sink, err := alert.NewCrowdSec(ctx, alert.CrowdSecConfig{
		URL: srv.URL, MachineID: "ran", Password: "secret",
		BatchInterval: 50 * time.Millisecond, BatchSize: 10,
	}, logger, m)
	if err != nil {
		t.Fatal(err)
	}
	sensor := alert.NewSensor(alert.SensorConfig{SummaryWindow: time.Hour, Metrics: m, IgnoreIPs: cfg.IgnoreIPs}, sink, logger)
	defer sensor.Close()

	tr := NewTelnet(cfg, logger, m, NewLimiter(cfg.MaxSessions, cfg.MaxPerIP), sensor)
	addr := serveTrap(t, ctx, tr)

	ignored := []string{"8.8.8.8", "1.1.1.77", "2606:4700:4700::1111", "::ffff:8.8.8.8"}
	for _, ip := range ignored {
		telnetAttempt(t, addr, ip)
	}
	waitFor(t, func() bool { return counterVal(t, m.Connections, "telnet", "completed") == float64(len(ignored)) })
	telnetAttempt(t, addr, "8.8.4.4")

	waitFor(t, func() bool { return lapi.acceptedCount() == 1 })
	time.Sleep(300 * time.Millisecond) // a wrongly queued ignored alert would be flushed by now

	if n := lapi.acceptedCount(); n != 1 {
		t.Fatalf("LAPI accepted %d alerts, want only the neighbor", n)
	}
	lapi.mu.Lock()
	body, _ := json.Marshal(lapi.accepted)
	lapi.mu.Unlock()
	if !strings.Contains(string(body), "8.8.4.4") {
		t.Errorf("neighbor alert missing: %s", body)
	}
	for _, ip := range []string{"8.8.8.8", "1.1.1.77", "2606:4700:4700::1111"} {
		if strings.Contains(string(body), ip) {
			t.Errorf("ignored source %s reached the LAPI: %s", ip, body)
		}
	}

	if got := counterVal(t, m.IgnoredSessions, "telnet"); got != float64(len(ignored)) {
		t.Errorf("ran_ignored_sessions_total{telnet} = %v, want %d", got, len(ignored))
	}
	if got := counterVal(t, m.CrowdSecPipeline, "telnet", "received"); got != 1 {
		t.Errorf("pipeline received = %v, want 1 (the neighbor only)", got)
	}

	var ignoredLines, neighborIgnored int
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) != nil || rec["protocol"] != "telnet" {
			continue
		}
		if rec["ignored"] == true {
			ignoredLines++
			if rec["source_ip"] == "8.8.4.4" {
				neighborIgnored++
			}
		}
	}
	if ignoredLines == 0 {
		t.Error("no log line carries ignored=true")
	}
	if neighborIgnored != 0 {
		t.Errorf("%d log lines of the neighbor carry ignored=true", neighborIgnored)
	}
	if !strings.Contains(logs.String(), `"action":"auth_attempt"`) {
		t.Error("ignored sessions must still be served and logged (auth_attempt missing)")
	}
}

// TestIgnoredSourceStillCountsAgainstLimiter: an ignored source is rejected like
// any other once it exceeds RAN_MAX_PER_IP.
func TestIgnoredSourceStillCountsAgainstLimiter(t *testing.T) {
	m := metrics.New(prometheus.NewRegistry(), "test")
	cfg := ignoreTelnetConfig(1, "8.8.8.8")
	sensor := alert.NewSensor(alert.SensorConfig{SummaryWindow: time.Hour, Metrics: m, IgnoreIPs: cfg.IgnoreIPs}, nil, quietLogger())
	defer sensor.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tr := NewTelnet(cfg, quietLogger(), m, NewLimiter(cfg.MaxSessions, cfg.MaxPerIP), sensor)
	addr := serveTrap(t, ctx, tr)

	first, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	fmt.Fprint(first, "PROXY TCP4 8.8.8.8 127.0.0.1 40000 23\r\n")
	waitFor(t, func() bool { return gaugeVal(t, m.ActiveSessions, "telnet") == 1 })

	second, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	fmt.Fprint(second, "PROXY TCP4 8.8.8.8 127.0.0.1 40001 23\r\n")
	waitFor(t, func() bool { return counterVal(t, m.SessionsRejected, "telnet") == 1 })
	expectClosed(t, second, 2*time.Second)

	if got := counterVal(t, m.IgnoredSessions, "telnet"); got != 1 {
		t.Errorf("ignored sessions = %v, want 1 (the rejected one never became a session)", got)
	}
}

func TestUDPIgnoredSourceIsLoggedAndCounted(t *testing.T) {
	logs := &syncBuffer{}
	m := metrics.New(prometheus.NewRegistry(), "test")
	cfg := &config.Config{
		Addrs:            map[string]string{"dns": "127.0.0.1:0"},
		SessionTimeout:   5 * time.Second,
		MaxSessions:      100,
		MaxPerIP:         10,
		UDPRatePerSource: 20, UDPRateBurst: 40, UDPRateGlobal: 2000,
		IgnoreIPs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
	}
	tr := NewDNS(cfg, newJSONLogger(logs), m, NewLimiter(cfg.MaxSessions, cfg.MaxPerIP))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := serveTrap(t, ctx, tr)

	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	query := append([]byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}, 3, 'a', 'b', 'c', 0, 0, 1, 0, 1)
	_, _ = c.Write(query)

	waitFor(t, func() bool { return counterVal(t, m.IgnoredSessions, "dns") == 1 })
	waitFor(t, func() bool { return strings.Contains(logs.String(), `"action":"disconnect"`) })
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		if strings.Contains(line, `"session_id"`) && !strings.Contains(line, `"ignored":true`) {
			t.Errorf("session log line without ignored=true: %s", line)
		}
	}
}

func TestNonIgnoredSessionsAreNotCounted(t *testing.T) {
	m := metrics.New(prometheus.NewRegistry(), "test")
	cfg := ignoreTelnetConfig(10, "8.8.8.8")
	sensor := alert.NewSensor(alert.SensorConfig{SummaryWindow: time.Hour, Metrics: m, IgnoreIPs: cfg.IgnoreIPs}, nil, quietLogger())
	defer sensor.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := serveTrap(t, ctx, NewTelnet(cfg, quietLogger(), m, NewLimiter(100, 10), sensor))

	telnetAttempt(t, addr, "1.1.1.1")
	waitFor(t, func() bool { return counterVal(t, m.Connections, "telnet", "completed") == 1 })
	if got := counterVal(t, m.IgnoredSessions, "telnet"); got != 0 {
		t.Errorf("ignored sessions = %v, want 0", got)
	}
}
