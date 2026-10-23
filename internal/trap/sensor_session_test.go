package trap

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/metrics"
)

func newTestSensor(t *testing.T, buf io.Writer) *alert.Sensor {
	t.Helper()
	s := alert.NewSensor(alert.SensorConfig{SummaryWindow: time.Hour}, nil, newJSONLogger(buf))
	t.Cleanup(s.Close)
	return s
}

func TestProbeSessionIsAggregatedNotLoggedPerSession(t *testing.T) {
	logs := &syncBuffer{}
	sensor := newTestSensor(t, logs)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")

	for range 20 {
		sess := NewSession("vnc", "tcp", "8.8.8.8", 40000, 5900, newJSONLogger(logs))
		sess.Sensor = sensor
		sess.LogConnect()
		sess.RecordStart(m)
		sess.LogDisconnect()
		sess.RecordEnd(m)
	}

	out := logs.String()
	if strings.Contains(out, "session started") || strings.Contains(out, "session ended") {
		t.Errorf("probe sessions must not log per-session lines:\n%s", out)
	}
	sensor.Close()
	out = logs.String()
	if got := strings.Count(out, `"action":"probe_summary"`); got != 1 {
		t.Fatalf("got %d summary lines, want 1:\n%s", got, out)
	}
	if !strings.Contains(out, `"sessions":20`) || !strings.Contains(out, `"vnc":20`) {
		t.Errorf("summary should count 20 vnc sessions:\n%s", out)
	}

	var c dto.Metric
	if err := m.Connections.WithLabelValues("vnc", "completed").Write(&c); err != nil {
		t.Fatal(err)
	}
	if c.GetCounter().GetValue() != 20 {
		t.Errorf("ran_connections_total{vnc} = %v, want 20 (metrics stay per session)", c.GetCounter().GetValue())
	}
}

func TestAttackSessionKeepsFullLinesInOrder(t *testing.T) {
	logs := &syncBuffer{}
	sensor := newTestSensor(t, logs)

	sess := NewSession("ssh", "tcp", "8.8.8.8", 40000, 22, newJSONLogger(logs))
	sess.Sensor = sensor
	sess.LogConnect()
	if strings.Contains(logs.String(), "session started") {
		t.Fatal("connect line should be held back until the session does something")
	}
	sess.LogAuthAttempt(slog.String("username", "root"))
	sess.LogDisconnect()

	out := logs.String()
	iStart := strings.Index(out, "session started")
	iCred := strings.Index(out, "credentials captured")
	iEnd := strings.Index(out, "session ended")
	if iStart < 0 || iCred < 0 || iEnd < 0 || iStart >= iCred || iCred >= iEnd {
		t.Errorf("want started < credentials < ended, got:\n%s", out)
	}
	if strings.Contains(out, "probe_summary") {
		t.Error("attack sessions must not be summarized")
	}
}

func TestSessionWithoutSensorLogsImmediately(t *testing.T) {
	logs := &syncBuffer{}
	sess := NewSession("dns", "udp", "8.8.8.8", 40000, 53, newJSONLogger(logs))
	sess.LogConnect()
	if !strings.Contains(logs.String(), "session started") {
		t.Error("sessions without a sensor keep the immediate connect line")
	}
	sess.LogDisconnect()
	if !strings.Contains(logs.String(), "session ended") {
		t.Error("sessions without a sensor keep the disconnect line")
	}
}

func TestSessionWithNoopAlerterStillLogsConnectAndEnd(t *testing.T) {
	logs := &syncBuffer{}
	sess := NewSession("vnc", "tcp", "8.8.8.8", 40000, 5900, newJSONLogger(logs))
	sess.Sensor = alert.NoopAlerter{}
	sess.LogConnect()
	sess.LogDisconnect()
	out := logs.String()
	if !strings.Contains(out, "session started") || !strings.Contains(out, "session ended") {
		t.Errorf("without aggregation both lines must appear:\n%s", out)
	}
}

func TestSessionAlertUsesSocketPeerAndCounters(t *testing.T) {
	rec := &recordingAlerter{}
	sess := NewSession("ssh", "tcp", "8.8.8.8", 40000, 2222, newJSONLogger(io.Discard))
	sess.Sensor = rec
	sess.LogAuthAttempt(slog.String("username", "root"))
	sess.LogCommand("id")
	sess.LogPayload("blob", slog.String("data", "abcde"))
	sess.Alert(context.Background(), map[string]string{"username": "root"})

	got := rec.snapshot()
	if len(got) != 1 || got[0].IP != "8.8.8.8" || got[0].Protocol != "ssh" {
		t.Fatalf("alerts = %+v, want one for ssh from 8.8.8.8", got)
	}
	info := sess.Info()
	if info.AuthAttempts != 1 || info.Commands != 1 || info.PayloadBytes != 5 || info.DestPort != 2222 || info.Transport != "tcp" {
		t.Errorf("info = %+v", info)
	}
	if info.AlertedClass != alert.ClassAttack {
		t.Errorf("AlertedClass = %q, want attack", info.AlertedClass)
	}
}

func TestPayloadWithoutStringAttrsCountsAtLeastOneByte(t *testing.T) {
	sess := NewSession("ntp", "tcp", "8.8.8.8", 1, 123, newJSONLogger(io.Discard))
	sess.LogPayload("ntp_request", slog.Int("version", 4))
	if got := sess.Info().PayloadBytes; got != 1 {
		t.Errorf("PayloadBytes = %d, want 1", got)
	}
}

func TestSessionAlertWithoutSensorIsNoop(t *testing.T) {
	sess := NewSession("dns", "udp", "8.8.8.8", 1, 53, newJSONLogger(io.Discard))
	sess.Alert(context.Background(), nil) // must not panic
}

// TestVNCProbeEndToEnd drives the real VNC trap: connections that only read the
// banner are probes, aggregated into one summary line.
func TestVNCProbeEndToEnd(t *testing.T) {
	t.Parallel()
	cfg := vncTestConfig(t)
	logs := &syncBuffer{}
	sensor := alert.NewSensor(alert.SensorConfig{SummaryWindow: time.Hour}, nil, newJSONLogger(logs))
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewVNC(cfg, newJSONLogger(logs), m, limiter, sensor)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg.Addrs["vnc"] = serveTrap(t, ctx, trap)

	for range 3 {
		conn, err := net.DialTimeout("tcp", cfg.TrapAddr("vnc"), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		var banner [12]byte
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(conn, banner[:]); err != nil {
			t.Fatal(err)
		}
		conn.Close()
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		total := 0.0
		for _, outcome := range []string{"completed", "error", "timeout"} {
			var c dto.Metric
			_ = m.Connections.WithLabelValues("vnc", outcome).Write(&c)
			total += c.GetCounter().GetValue()
		}
		if total >= 3 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = trap.Stop(context.Background())
	sensor.Close()

	out := logs.String()
	if strings.Contains(out, `"action":"connect"`) || strings.Contains(out, `"action":"disconnect"`) {
		t.Errorf("probe sessions produced per-session lines:\n%s", out)
	}
	if got := strings.Count(out, `"action":"probe_summary"`); got != 1 {
		t.Errorf("got %d summary lines, want 1:\n%s", got, out)
	}
}
