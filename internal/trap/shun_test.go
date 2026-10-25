package trap

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

type shunClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *shunClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *shunClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func collectSum(t *testing.T, c prometheus.Collector) float64 {
	t.Helper()
	ch := make(chan prometheus.Metric, 8)
	c.Collect(ch)
	close(ch)
	var sum float64
	for m := range ch {
		var d dto.Metric
		if err := m.Write(&d); err != nil {
			t.Fatal(err)
		}
		if d.Counter != nil {
			sum += d.Counter.GetValue()
		}
		if d.Gauge != nil {
			sum += d.Gauge.GetValue()
		}
	}
	return sum
}

// proxiedAttempt dials the trap, claims src through a PROXY header, sends one
// telnet login and returns everything the trap sent before it closed.
func proxiedAttempt(t *testing.T, addr, src string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "PROXY TCP4 %s 127.0.0.1 40000 23\r\n", src)
	fmt.Fprint(conn, "root\r\nsecret\r\n")
	out, _ := io.ReadAll(bufio.NewReader(conn)) // the trap closes after one attempt
	return string(out)
}

// TestShunClosesRepeatConnectionsOnTCPTrap runs a real telnet trap with a real
// Sensor and CrowdSec sink: after the alert the source is closed at accept time
// without a session, and served again once the window passed.
func TestShunClosesRepeatConnectionsOnTCPTrap(t *testing.T) {
	t.Parallel()
	lapi := &fakeLAPI{}
	srv := httptest.NewServer(lapi.handler())
	defer srv.Close()

	buf := &syncBuffer{}
	logger := newJSONLogger(buf)
	m := metrics.New(prometheus.NewRegistry(), "test")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clk := &shunClock{now: time.Unix(1_700_000_000, 0)}
	sink, err := alert.NewCrowdSec(ctx, alert.CrowdSecConfig{
		URL: srv.URL, MachineID: "ran", Password: "secret",
		Cooldown: time.Hour, BatchInterval: 100 * time.Millisecond, BatchSize: 10,
		Shun: true, Now: clk.Now,
	}, logger, m)
	if err != nil {
		t.Fatal(err)
	}
	sensor := alert.NewSensor(alert.SensorConfig{SummaryWindow: time.Hour, Metrics: m}, sink, logger)
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
	src := "8.8.8.8"

	if out := proxiedAttempt(t, addr, src); !strings.Contains(out, "Login") {
		t.Fatalf("first connection was not served: %q", out)
	}
	if !sensor.Shunned(src) {
		t.Fatal("source is not shunned after the alert")
	}
	logged := strings.Count(buf.String(), src)

	// Second connection: closed at accept time, no banner, no session lines.
	if out := proxiedAttempt(t, addr, src); out != "" {
		t.Errorf("shunned connection received data: %q", out)
	}
	if got := collectSum(t, m.ConnectionsRejected); got != 1 {
		t.Errorf("ran_connections_rejected_total = %v, want 1", got)
	}
	if got := strings.Count(buf.String(), src); got != logged {
		t.Errorf("shunned connection produced %d log lines mentioning the source", got-logged)
	}
	// Another source is unaffected.
	if out := proxiedAttempt(t, addr, "1.1.1.1"); !strings.Contains(out, "Login") {
		t.Errorf("other source was not served: %q", out)
	}

	// After the window the connection is served again, the summary is written
	// once.
	clk.Advance(2 * time.Hour)
	if out := proxiedAttempt(t, addr, src); !strings.Contains(out, "Login") {
		t.Errorf("connection after the window was not served: %q", out)
	}
	if n := strings.Count(buf.String(), "shun summary"); n != 1 {
		t.Errorf("got %d shun summary lines, want 1", n)
	}
	if !strings.Contains(buf.String(), `"count":1`) {
		t.Errorf("summary count is not 1:\n%s", buf.String())
	}
}

// shunAll is a Reporter that shuns every source.
type shunAll struct {
	alert.NoopAlerter
	mu       sync.Mutex
	rejected int
}

func (s *shunAll) Shunned(string) bool { return true }
func (s *shunAll) ShunRejected(string, string) {
	s.mu.Lock()
	s.rejected++
	s.mu.Unlock()
}

func TestShunListenerClosesHTTPConnections(t *testing.T) {
	t.Parallel()
	cfg := httpTestConfig(t)
	m := metrics.New(prometheus.NewRegistry(), "test")
	rep := &shunAll{}
	tr := NewHTTP(cfg, newJSONLogger(&syncBuffer{}), m, NewLimiter(cfg.MaxSessions, cfg.MaxPerIP), rep)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := serveTrap(t, ctx, tr)

	client := &http.Client{Timeout: 3 * time.Second}
	if resp, err := client.Get("http://" + addr + "/"); err == nil {
		resp.Body.Close()
		t.Fatal("shunned HTTP connection was served")
	}
	rep.mu.Lock()
	n := rep.rejected
	rep.mu.Unlock()
	if n == 0 {
		t.Error("ShunRejected was not called")
	}
	if got := collectSum(t, m.ActiveSessions); got != 0 {
		t.Errorf("active sessions = %v, want 0", got)
	}
}

func TestReporterWithoutShunnerNeverShuns(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if closeIfShunned(alert.NoopAlerter{}, "ssh", a) {
		t.Error("NoopAlerter shunned a connection")
	}
	if closeIfShunned(nil, "ssh", a) {
		t.Error("nil reporter shunned a connection")
	}
}

type plainReporter struct{}

func (plainReporter) Alert(context.Context, alert.SessionInfo, map[string]string) alert.Class {
	return ""
}
func (plainReporter) SessionEnd(alert.SessionInfo) bool { return false }

// gateSink is a sink that carries a shun gate, like the CrowdSec sink does.
type gateSink struct{ shun bool }

func (gateSink) Submit(context.Context, alert.Event) {}
func (gateSink) Close()                              {}
func (g gateSink) ShunEnabled() bool                 { return g.shun }
func (gateSink) Shunned(string) bool                 { return false }
func (gateSink) ShunRejected(string, string)         {}
func (gateSink) Sweep()                              {}
func (gateSink) Flush()                              {}

func TestCanShun(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sensor := alert.NewSensor(alert.SensorConfig{}, gateSink{shun: true}, logger)
	defer sensor.Close()
	if !CanShun(sensor) {
		t.Error("a sensor whose sink has an enabled shun gate must be able to shun")
	}
	noGate := alert.NewSensor(alert.SensorConfig{}, nil, logger)
	defer noGate.Close()
	if CanShun(noGate) {
		t.Error("a sensor without a shun gate must not be reported as able to shun")
	}
	gateOff := alert.NewSensor(alert.SensorConfig{}, gateSink{}, logger)
	defer gateOff.Close()
	if CanShun(gateOff) {
		t.Error("a sensor whose gate has shun off must not be reported as able to shun")
	}
	if CanShun(plainReporter{}) {
		t.Error("a reporter without Shunned/ShunRejected must not be reported as able to shun")
	}
	if CanShun(nil) {
		t.Error("nil reporter must not be reported as able to shun")
	}
}
