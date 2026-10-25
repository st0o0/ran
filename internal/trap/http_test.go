package trap

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

func httpTestConfig(t *testing.T) *config.Config {
	t.Helper()
	addr := "127.0.0.1:0"

	cfg := &config.Config{
		Traps:          []string{"http"},
		Addrs:          map[string]string{"http": addr},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}
	cfg.SetFingerprint(testProfile)
	return cfg
}

func TestHTTPLoginPage(t *testing.T) {
	t.Parallel()
	cfg := httpTestConfig(t)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewHTTP(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg.Addrs["http"] = serveTrap(t, ctx, trap)

	resp, err := http.Get("http://" + cfg.TrapAddr("http") + "/wp-login.php")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "WordPress") {
		t.Error("body should contain WordPress")
	}
}

func TestHTTPCredentialCapture(t *testing.T) {
	t.Parallel()
	cfg := httpTestConfig(t)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewHTTP(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg.Addrs["http"] = serveTrap(t, ctx, trap)

	resp, err := http.Post(
		"http://"+cfg.TrapAddr("http")+"/wp-login.php",
		"application/x-www-form-urlencoded",
		strings.NewReader("log=admin&pwd=secret123"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestHTTPAdminPage(t *testing.T) {
	t.Parallel()
	cfg := httpTestConfig(t)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewHTTP(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg.Addrs["http"] = serveTrap(t, ctx, trap)

	resp, err := http.Post(
		"http://"+cfg.TrapAddr("http")+"/admin",
		"application/x-www-form-urlencoded",
		strings.NewReader("username=admin&password=pass"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if !strings.Contains(string(body), "Invalid credentials") {
		t.Error("body should contain error message")
	}
}

func TestHTTPResponseHeaders(t *testing.T) {
	t.Parallel()
	cfg := httpTestConfig(t)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewHTTP(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg.Addrs["http"] = serveTrap(t, ctx, trap)

	resp, err := http.Get("http://" + cfg.TrapAddr("http") + "/admin")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Server"); got != testProfile.HTTP.Server {
		t.Errorf("Server header = %q, want %q", got, testProfile.HTTP.Server)
	}
	if got := resp.Header.Get("X-Powered-By"); got != testProfile.HTTP.PoweredBy() {
		t.Errorf("X-Powered-By = %q, want %q", got, testProfile.HTTP.PoweredBy())
	}
}

// Two connections that report the same RemoteAddr (possible under PROXY
// protocol) must get separate sessions and must not leak limiter slots.
func TestHTTPSessionsAreKeyedPerConnection(t *testing.T) {
	cfg := httpTestConfig(t)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	lim := NewLimiter(10, 10)
	tr := NewHTTP(cfg, slog.New(slog.NewJSONHandler(io.Discard, nil)), m, lim, alert.NoopAlerter{})

	a1, b1 := net.Pipe()
	a2, b2 := net.Pipe()
	defer b1.Close()
	defer b2.Close()
	defer a1.Close()
	defer a2.Close()

	ctx1 := tr.connContext(context.Background(), a1)
	ctx2 := tr.connContext(context.Background(), a2)
	tr.connState(a1, http.StateNew)
	tr.connState(a2, http.StateNew)

	hc1, _ := ctx1.Value(httpConnKey{}).(*httpConn)
	hc2, _ := ctx2.Value(httpConnKey{}).(*httpConn)
	if hc1 == nil || hc2 == nil || hc1.sess == nil || hc2.sess == nil || hc1.sess == hc2.sess {
		t.Fatal("each connection must own a distinct session")
	}
	if lim.global != 2 {
		t.Fatalf("limiter holds %d slots, want 2", lim.global)
	}

	tr.connState(a1, http.StateClosed)
	tr.connState(a2, http.StateHijacked)
	if lim.global != 0 || len(lim.perIP) != 0 {
		t.Errorf("limiter leaked: global=%d perIP=%v", lim.global, lim.perIP)
	}
	n := 0
	tr.conns.Range(func(_, _ any) bool { n++; return true })
	if n != 0 {
		t.Errorf("%d connection entries left behind", n)
	}
}
