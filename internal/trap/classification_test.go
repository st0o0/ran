package trap

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

// eventSink records the events a real Sensor forwards, so tests can assert the
// probe versus attack outcome of a trap session.
type eventSink struct {
	mu     sync.Mutex
	events []alert.Event
}

func (s *eventSink) Submit(_ context.Context, ev alert.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
}

func (s *eventSink) Close() {}

func (s *eventSink) snapshot() []alert.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]alert.Event(nil), s.events...)
}

// waitEvents waits until pred is true for the current events (5s deadline).
func (s *eventSink) waitEvents(t *testing.T, pred func([]alert.Event) bool) []alert.Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		evs := s.snapshot()
		if pred(evs) {
			return evs
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for events, have %+v", evs)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func hasClass(evs []alert.Event, c alert.Class) bool {
	for _, e := range evs {
		if e.Class == c {
			return true
		}
	}
	return false
}

// waitClass waits for the first event, which for probes only arrives when the
// session ends, and returns the highest class seen.
func (s *eventSink) waitOutcome(t *testing.T) alert.Class {
	t.Helper()
	evs := s.waitEvents(t, func(e []alert.Event) bool { return len(e) > 0 })
	var out alert.Class
	for _, e := range evs {
		out = alert.MaxClass(out, e.Class)
	}
	return out
}

type trapBuilder func(*config.Config, *slog.Logger, *metrics.Metrics, *Limiter, Reporter) Trap

// startSensorTrap starts a trap wired to a real Sensor with a recording sink.
func startSensorTrap(t *testing.T, name string, build trapBuilder) (string, *eventSink) {
	t.Helper()
	addr := "127.0.0.1:0"

	cfg := &config.Config{
		Addrs:          map[string]string{name: addr},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}
	sink := &eventSink{}
	sensor := alert.NewSensor(alert.SensorConfig{SummaryWindow: time.Hour}, sink, slog.New(slog.NewTextHandler(io.Discard, nil)))
	m := metrics.New(prometheus.NewRegistry(), "test")
	tr := build(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), m, NewLimiter(cfg.MaxSessions, cfg.MaxPerIP), sensor)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(sensor.Close)
	t.Cleanup(cancel)
	addr = serveTrap(t, ctx, tr)
	return addr, sink
}

func dialTrap(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { conn.Close() })
	return conn
}

func commandMeta(evs []alert.Event) string {
	for _, e := range evs {
		if c, ok := e.Meta["command"]; ok {
			return c
		}
	}
	return ""
}

// --- commandName / AlertCommand ---

func TestCommandNameIsBounded(t *testing.T) {
	cases := map[string]string{
		"INFO":                       "INFO",
		"  GET secretkey and more  ": "GET",
		"CONFIG\tSET dir /tmp":       "CONFIG",
		"":                           "",
	}
	for in, want := range cases {
		if got := commandName(in); got != want {
			t.Errorf("commandName(%q) = %q, want %q", in, got, want)
		}
	}
	long := commandName(strings.Repeat("A", 500) + " arg")
	if len(long) != maxCommandNameBytes {
		t.Errorf("long name length = %d, want %d", len(long), maxCommandNameBytes)
	}
	multi := commandName(strings.Repeat("€", 50))
	if !utf8.ValidString(multi) || len(multi) > maxCommandNameBytes {
		t.Errorf("multi-byte name = %q (%d bytes), want valid and <= %d", multi, len(multi), maxCommandNameBytes)
	}
}

func TestAlertCommandSendsNameOnlyAndOnlyOnce(t *testing.T) {
	rec := &recordingAlerter{}
	sess := NewSession("redis", "tcp", "8.8.8.8", 40000, 6379, newJSONLogger(io.Discard))
	sess.Sensor = rec
	for i := 0; i < 20; i++ {
		line := fmt.Sprintf("SET secret%d value", i)
		sess.LogCommand(line)
		sess.AlertCommand(context.Background(), line)
	}
	got := rec.snapshot()
	if len(got) != 1 {
		t.Fatalf("got %d alerts for 20 commands, want 1 (cheap)", len(got))
	}
	if got[0].Meta["command"] != "SET" || len(got[0].Meta) != 1 {
		t.Errorf("meta = %v, want only command=SET", got[0].Meta)
	}
}

// --- Elasticsearch ---

func startESSensor(t *testing.T) (string, *eventSink) {
	return startSensorTrap(t, "elasticsearch", func(c *config.Config, l *slog.Logger, m *metrics.Metrics, lim *Limiter, a Reporter) Trap {
		return NewElasticsearch(c, l, m, lim, a)
	})
}

func TestElasticsearchFingerprintGETsStayProbes(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"/", "/_cluster/health", "/_nodes", "/_cat/indices"} {
		t.Run(path, func(t *testing.T) {
			addr, sink := startESSensor(t)
			resp, err := http.Get("http://" + addr + path)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if got := sink.waitOutcome(t); got != alert.ClassProbe {
				t.Errorf("GET %s outcome = %s, want probe", path, got)
			}
			if hasClass(sink.snapshot(), alert.ClassAttack) {
				t.Errorf("GET %s produced an attack event", path)
			}
		})
	}
}

func TestElasticsearchWritesAndBodiesAreAttacks(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"post search", "POST", "/_search", `{"query":{"match_all":{}}}`},
		{"put", "PUT", "/idx", `{}`},
		{"delete without body", "DELETE", "/idx", ""},
		{"get with body", "GET", "/_search", `{"query":{}}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			addr, sink := startESSensor(t)
			req, _ := http.NewRequest(c.method, "http://"+addr+c.path, strings.NewReader(c.body))
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			sink.waitEvents(t, func(e []alert.Event) bool { return hasClass(e, alert.ClassAttack) })
		})
	}
}

// --- Minecraft ---

func startMinecraftSensor(t *testing.T) (string, *eventSink) {
	return startSensorTrap(t, "minecraft", func(c *config.Config, l *slog.Logger, m *metrics.Metrics, lim *Limiter, a Reporter) Trap {
		return NewMinecraft(c, l, m, lim, a)
	})
}

func TestMinecraftServerListPingStaysProbe(t *testing.T) {
	t.Parallel()
	addr, sink := startMinecraftSensor(t)
	conn := dialTrap(t, addr)
	_, _ = conn.Write(mcBuildHandshake(767, "localhost", 25565, 1))
	_, _ = conn.Write(mcWritePacket(0x00, nil)) // status request
	buf := make([]byte, 64)
	if _, err := conn.Read(buf); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if got := sink.waitOutcome(t); got != alert.ClassProbe {
		t.Errorf("status ping outcome = %s, want probe", got)
	}
	if hasClass(sink.snapshot(), alert.ClassAttack) {
		t.Error("status ping must not produce an attack event")
	}
}

func TestMinecraftLoginWithPlayerNameIsAttack(t *testing.T) {
	t.Parallel()
	addr, sink := startMinecraftSensor(t)
	conn := dialTrap(t, addr)
	_, _ = conn.Write(mcBuildHandshake(767, "localhost", 25565, 2))
	_, _ = conn.Write(mcWritePacket(0x00, mcWriteString("Steve")))
	buf := make([]byte, 64)
	_, _ = conn.Read(buf)
	conn.Close()
	sink.waitEvents(t, func(e []alert.Event) bool { return hasClass(e, alert.ClassAttack) })
}

// --- Command meta for redis, memcached, imap and irc ---

func TestRedisCommandAlertsImmediatelyWithCommandMeta(t *testing.T) {
	t.Parallel()
	addr, sink := startSensorTrap(t, "redis", func(c *config.Config, l *slog.Logger, m *metrics.Metrics, lim *Limiter, a Reporter) Trap {
		return NewRedis(c, l, m, lim, a)
	})
	conn := dialTrap(t, addr)
	fmt.Fprint(conn, "CONFIG SET dir /tmp\r\n")
	if _, err := bufio.NewReader(conn).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	// The session is still open: the alert must not wait for the session end.
	evs := sink.waitEvents(t, func(e []alert.Event) bool { return hasClass(e, alert.ClassAttack) })
	if got := commandMeta(evs); got != "CONFIG" {
		t.Errorf("command meta = %q, want CONFIG (name only, no arguments)", got)
	}
}

func TestMemcachedConnectIsProbeCommandIsAttack(t *testing.T) {
	t.Parallel()
	builder := func(c *config.Config, l *slog.Logger, m *metrics.Metrics, lim *Limiter, a Reporter) Trap {
		return NewMemcached(c, l, m, lim, a)
	}
	addr, sink := startSensorTrap(t, "memcached", builder)
	conn := dialTrap(t, addr)
	conn.Close()
	if got := sink.waitOutcome(t); got != alert.ClassProbe {
		t.Errorf("connect-only outcome = %s, want probe", got)
	}

	addr, sink = startSensorTrap(t, "memcached", builder)
	conn = dialTrap(t, addr)
	time.Sleep(100 * time.Millisecond)
	if n := len(sink.snapshot()); n != 0 {
		t.Fatalf("connect must not alert, got %d events", n)
	}
	fmt.Fprint(conn, "stats items\r\n")
	if _, err := bufio.NewReader(conn).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	evs := sink.waitEvents(t, func(e []alert.Event) bool { return hasClass(e, alert.ClassAttack) })
	if got := commandMeta(evs); got != "stats" {
		t.Errorf("command meta = %q, want stats", got)
	}
}

func TestIMAPUnknownCommandAlertsWithCommandMeta(t *testing.T) {
	t.Parallel()
	addr, sink := startSensorTrap(t, "imap", func(c *config.Config, l *slog.Logger, m *metrics.Metrics, lim *Limiter, a Reporter) Trap {
		return NewIMAP(c, l, m, lim, a)
	})
	conn := dialTrap(t, addr)
	r := bufio.NewReader(conn)
	if _, err := r.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(conn, "a1 SELECT INBOX\r\n")
	if _, err := r.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	evs := sink.waitEvents(t, func(e []alert.Event) bool { return hasClass(e, alert.ClassAttack) })
	if got := commandMeta(evs); got != "SELECT" {
		t.Errorf("command meta = %q, want SELECT", got)
	}
}

func TestIRCUnknownCommandAlertsWithCommandMeta(t *testing.T) {
	t.Parallel()
	addr, sink := startSensorTrap(t, "irc", func(c *config.Config, l *slog.Logger, m *metrics.Metrics, lim *Limiter, a Reporter) Trap {
		return NewIRC(c, l, m, lim, a)
	})
	conn := dialTrap(t, addr)
	fmt.Fprint(conn, "JOIN #secret key\r\n")
	evs := sink.waitEvents(t, func(e []alert.Event) bool { return hasClass(e, alert.ClassAttack) })
	if got := commandMeta(evs); got != "JOIN" {
		t.Errorf("command meta = %q, want JOIN", got)
	}
}
