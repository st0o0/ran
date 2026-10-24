package trap

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

type bannerEnv struct {
	addrs   []string
	sink    *eventSink
	logs    *syncBuffer
	metrics *metrics.Metrics
	reg     *prometheus.Registry
	trap    *BannerTrap
}

func bannerConfig(services ...config.BannerService) *config.Config {
	return &config.Config{
		BannerServices: services,
		PerProto:       make(map[string]config.ProtoConfig),
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}
}

// startBanner starts a banner trap on loopback port 0 for every service behind
// a real sensor.
func startBanner(t *testing.T, cfg *config.Config, ignore ...string) bannerEnv {
	t.Helper()
	sink := &eventSink{}
	logs := &syncBuffer{}
	logger := newJSONLogger(logs)
	prefixes, err := config.ParseIgnoreList("RAN_IGNORE_IPS", strings.Join(ignore, ","))
	if err != nil {
		t.Fatal(err)
	}
	cfg.IgnoreIPs = prefixes
	sensor := alert.NewSensor(alert.SensorConfig{SummaryWindow: time.Hour, IgnoreIPs: prefixes}, sink, logger)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	tr, err := newBanner(cfg, logger, m, NewLimiter(cfg.MaxSessions, cfg.MaxPerIP), sensor, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(sensor.Close)
	t.Cleanup(cancel)
	serveTrap(t, ctx, tr)
	var addrs []string
	for _, a := range tr.Addrs() {
		addrs = append(addrs, a.String())
	}
	return bannerEnv{addrs: addrs, sink: sink, logs: logs, metrics: m, reg: reg, trap: tr}
}

func svc(name, banner string) config.BannerService {
	return config.BannerService{Name: name, Banner: []byte(banner)}
}

func TestBannerSentOnConnectPerService(t *testing.T) {
	t.Parallel()
	env := startBanner(t, bannerConfig(svc("custom", "hello\r\n"), svc("other", "220 other ready\r\n")))
	if len(env.addrs) != 2 || env.addrs[0] == env.addrs[1] {
		t.Fatalf("addrs = %v", env.addrs)
	}
	for i, want := range []string{"hello\r\n", "220 other ready\r\n"} {
		c := dialTrap(t, env.addrs[i])
		got := make([]byte, len(want))
		if _, err := io.ReadFull(c, got); err != nil {
			t.Fatalf("service %d: %v", i, err)
		}
		if string(got) != want {
			t.Errorf("service %d banner = %q, want %q", i, got, want)
		}
	}
}

func TestBannerClientLineIsCommandAndAttack(t *testing.T) {
	t.Parallel()
	env := startBanner(t, bannerConfig(svc("custom", "hello\r\n")))
	c := dialTrap(t, env.addrs[0])
	if _, err := c.Write([]byte("STAT\r\nVERSION x y z\r\n")); err != nil {
		t.Fatal(err)
	}
	line := waitLog(t, env.logs, func(m map[string]any) bool { return m["action"] == "command" && m["command"] == "VERSION x y z" })
	if line["service"] != "custom" {
		t.Errorf("command line = %v", line)
	}
	waitLog(t, env.logs, func(m map[string]any) bool { return m["action"] == "command" && m["command"] == "STAT" })

	evs := env.sink.waitEvents(t, func(e []alert.Event) bool { return hasClass(e, alert.ClassAttack) })
	if commandMeta(evs) != "STAT" {
		t.Errorf("alert command meta = %q, want STAT", commandMeta(evs))
	}
	for _, e := range evs {
		if e.Meta["service"] != "custom" {
			t.Errorf("alert meta = %v, want service=custom", e.Meta)
		}
	}
}

func TestBannerConnectWithoutDataIsProbe(t *testing.T) {
	t.Parallel()
	env := startBanner(t, bannerConfig(svc("custom", "hello\r\n")))
	c := dialTrap(t, env.addrs[0])
	buf := make([]byte, 7)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	c.Close()
	if got := env.sink.waitOutcome(t); got != alert.ClassProbe {
		t.Errorf("class = %s, want probe", got)
	}
	if hasClass(env.sink.snapshot(), alert.ClassAttack) {
		t.Error("probe produced an attack")
	}
	waitFor(t, func() bool { return counterVal(t, env.metrics.Connections, "banner", "probe") == 1 })
}

func TestBannerIdleUntilTimeoutIsProbe(t *testing.T) {
	t.Parallel()
	cfg := bannerConfig(svc("custom", "hi\n"))
	cfg.SessionTimeout = 200 * time.Millisecond
	env := startBanner(t, cfg)
	c := dialTrap(t, env.addrs[0])
	_, _ = io.Copy(io.Discard, c)
	waitFor(t, func() bool { return counterVal(t, env.metrics.Connections, "banner", "probe") == 1 })
}

func TestBannerOverlongLineIsPayloadAndBounded(t *testing.T) {
	t.Parallel()
	env := startBanner(t, bannerConfig(svc("custom", "hi\n")))
	c := dialTrap(t, env.addrs[0])
	if _, err := c.Write([]byte(strings.Repeat("A", 2000))); err != nil {
		t.Fatal(err)
	}
	line := waitLog(t, env.logs, func(m map[string]any) bool { return m["payload_type"] == "banner_overlong" })
	if line["service"] != "custom" {
		t.Errorf("line = %v", line)
	}
	env.sink.waitEvents(t, func(e []alert.Event) bool { return hasClass(e, alert.ClassAttack) })
	waitFor(t, func() bool { return counterVal(t, env.metrics.Connections, "banner", "too_long") == 1 })
	for _, l := range logLines(t, env.logs) {
		for k, v := range l {
			if s, ok := v.(string); ok && len(s) > 600 {
				t.Errorf("log field %s holds %d bytes", k, len(s))
			}
		}
	}
}

func TestBannerUnterminatedLineBeforeCloseIsLogged(t *testing.T) {
	t.Parallel()
	env := startBanner(t, bannerConfig(svc("custom", "hi\n")))
	c := dialTrap(t, env.addrs[0])
	_, _ = io.ReadFull(c, make([]byte, 3)) // read the banner first: closing with unread input resets the connection
	if _, err := c.Write([]byte("GET / HTTP/1.0")); err != nil {
		t.Fatal(err)
	}
	c.Close()
	waitLog(t, env.logs, func(m map[string]any) bool { return m["action"] == "command" && m["command"] == "GET / HTTP/1.0" })
	env.sink.waitEvents(t, func(e []alert.Event) bool { return hasClass(e, alert.ClassAttack) })
}

func TestBannerLineCountIsBounded(t *testing.T) {
	t.Parallel()
	env := startBanner(t, bannerConfig(svc("custom", "hi\n")))
	c := dialTrap(t, env.addrs[0])
	go func() {
		_, _ = c.Write([]byte(strings.Repeat("x\n", maxBannerLines*3)))
	}()
	_, _ = io.Copy(io.Discard, c)
	waitFor(t, func() bool { return counterVal(t, env.metrics.Connections, "banner", "completed") == 1 })
	n := 0
	for _, l := range logLines(t, env.logs) {
		if l["action"] == "command" {
			n++
		}
	}
	if n != maxBannerLines {
		t.Errorf("logged %d commands, want %d", n, maxBannerLines)
	}
}

// Control characters never reach the log, and the service name is sanitized.
func TestBannerSanitizesInput(t *testing.T) {
	t.Parallel()
	env := startBanner(t, bannerConfig(svc("we\x1b[31mird", "hi\n")))
	c := dialTrap(t, env.addrs[0])
	if _, err := c.Write([]byte("A\x1b[2Jb\x00c\r\n")); err != nil {
		t.Fatal(err)
	}
	line := waitLog(t, env.logs, func(m map[string]any) bool { return m["action"] == "command" })
	if strings.ContainsAny(line["command"].(string), "\x1b\x00") || strings.ContainsAny(line["service"].(string), "\x1b") {
		t.Errorf("unsanitized line: %v", line)
	}
}

// The protocol label of every metric is the fixed string banner; the configured
// name never becomes a label.
func TestBannerMetricLabelIsFixed(t *testing.T) {
	t.Parallel()
	env := startBanner(t, bannerConfig(svc("secretname", "hi\n"), svc("second", "yo\n")))
	for _, a := range env.addrs {
		c := dialTrap(t, a)
		_, _ = c.Write([]byte("x\n"))
		_, _ = io.Copy(io.Discard, io.LimitReader(c, 3))
		c.Close()
	}
	waitFor(t, func() bool { return counterVal(t, env.metrics.Connections, "banner", "completed") == 2 })
	families, err := env.reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "protocol" && l.GetValue() != "banner" {
					t.Errorf("metric %s has protocol label %q", f.GetName(), l.GetValue())
				}
				if strings.Contains(l.GetValue(), "secretname") || strings.Contains(l.GetValue(), "second") {
					t.Errorf("metric %s leaks the service name: %q", f.GetName(), l.GetValue())
				}
			}
		}
	}
}

func TestNewBannerWithoutServicesFails(t *testing.T) {
	t.Parallel()
	if _, err := NewBanner(bannerConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil, NewLimiter(1, 1), alert.NoopAlerter{}); err == nil || !strings.Contains(err.Error(), "RAN_BANNER_SERVICES") {
		t.Errorf("err = %v, want it to name RAN_BANNER_SERVICES", err)
	}
	if _, err := Registry["banner"](bannerConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil, NewLimiter(1, 1), alert.NoopAlerter{}); err == nil {
		t.Error("registry factory accepted a config without services")
	}
}

// Binding is all or nothing: a busy port makes Start fail and releases the
// other ports.
func TestBannerBindFailureReleasesOtherPorts(t *testing.T) {
	t.Parallel()
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	freePort := free.Addr().(*net.TCPAddr).Port
	free.Close()

	cfg := bannerConfig(
		config.BannerService{Port: freePort, Name: "a", Banner: []byte("a\n")},
		config.BannerService{Port: busy.Addr().(*net.TCPAddr).Port, Name: "b", Banner: []byte("b\n")},
	)
	tr, err := newBanner(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), metrics.New(prometheus.NewRegistry(), "test"), NewLimiter(10, 10), alert.NoopAlerter{}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() { errc <- tr.Start(context.Background()) }()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("Start succeeded although a port is busy")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return")
	}
	waitFor(t, func() bool {
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", freePort))
		if err != nil {
			return false
		}
		l.Close()
		return true
	})
	if err := tr.Stop(context.Background()); err != nil {
		t.Errorf("Stop after failed start: %v", err)
	}
}

// An ignored source gets the same service but never produces an event.
func TestBannerIgnoredSourceNeverAlerts(t *testing.T) {
	t.Parallel()
	proxyDial := func(t *testing.T, addr string) net.Conn {
		c := dialTrap(t, addr)
		if _, err := fmt.Fprint(c, "PROXY TCP4 8.8.8.8 1.1.1.1 40000 80\r\n"); err != nil {
			t.Fatal(err)
		}
		return c
	}

	cfg := bannerConfig(svc("custom", "hello\r\n"))
	cfg.ProxyProtocol = true
	env := startBanner(t, cfg, "8.8.8.8")
	c := proxyDial(t, env.addrs[0])
	got := make([]byte, 7)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "hello\r\n" {
		t.Fatalf("banner for an ignored source: %q, %v", got, err)
	}
	_, _ = c.Write([]byte("STAT\r\n"))
	waitLog(t, env.logs, func(m map[string]any) bool { return m["action"] == "command" && m["ignored"] == true })
	time.Sleep(100 * time.Millisecond)
	if evs := env.sink.snapshot(); len(evs) != 0 {
		t.Errorf("ignored banner source produced events: %+v", evs)
	}
}

// A client that connects and never reads or writes must not hold the session
// past its deadline or block shutdown. The 256 byte banner always fits in the
// loopback socket buffers, so the write itself cannot be made to block here; the
// test covers the session deadline and Stop with an idle, non-reading peer.
func TestBannerNonReadingClientDoesNotBlockShutdown(t *testing.T) {
	t.Parallel()
	cfg := bannerConfig(svc("custom", strings.Repeat("B", config.MaxBannerBytes)))
	cfg.SessionTimeout = 300 * time.Millisecond
	env := startBanner(t, cfg)
	c := dialTrap(t, env.addrs[0])
	_ = c // never read, never write

	start := time.Now()
	waitFor(t, func() bool { return counterVal(t, env.metrics.Connections, "banner", "probe") == 1 })
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("session lasted %v, want about the 300ms deadline", d)
	}

	// A second idle client is still open when Stop is called.
	c2 := dialTrap(t, env.addrs[0])
	_ = c2
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start = time.Now()
	if err := env.trap.Stop(ctx); err != nil {
		t.Errorf("Stop: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("Stop took %v", d)
	}
}

func TestBannerSecretHeadersFollowPasswordMode(t *testing.T) {
	defer SetPasswordLogMode("off")
	for _, tc := range []struct{ mode, want string }{
		{"off", "Authorization:"},
		{"mask", "Authorization: *** (14)"},
		{"on", "Authorization: Basic c2VjcmV0"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			SetPasswordLogMode(tc.mode)
			env := startBanner(t, bannerConfig(svc("custom", "hi\n")))
			c := dialTrap(t, env.addrs[0])
			if _, err := c.Write([]byte("Authorization: Basic c2VjcmV0\r\n")); err != nil {
				t.Fatal(err)
			}
			line := waitLog(t, env.logs, func(m map[string]any) bool { return m["action"] == "command" })
			if line["command"] != tc.want {
				t.Errorf("command = %q, want %q", line["command"], tc.want)
			}
			if tc.mode != "on" && strings.Contains(env.logs.String(), "c2VjcmV0") {
				t.Errorf("secret in log: %s", env.logs.String())
			}
		})
	}
}
