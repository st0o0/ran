package trap

import (
	"bufio"
	"context"
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

// stubHarness is a stub trap wired to a real Sensor, a recording sink and a log
// buffer.
type stubHarness struct {
	addr string
	sink *eventSink
	logs *syncBuffer
	trap Trap
}

func startStub(t *testing.T, name string, build trapBuilder) *stubHarness {
	t.Helper()
	cfg := &config.Config{
		Addrs:          map[string]string{name: "127.0.0.1:0"},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}
	h := &stubHarness{sink: &eventSink{}, logs: &syncBuffer{}}
	sensor := alert.NewSensor(alert.SensorConfig{SummaryWindow: time.Hour}, h.sink, slog.New(slog.NewTextHandler(io.Discard, nil)))
	m := metrics.New(prometheus.NewRegistry(), "test")
	h.trap = build(cfg, newJSONLogger(h.logs), m, NewLimiter(cfg.MaxSessions, cfg.MaxPerIP), sensor)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(sensor.Close)
	t.Cleanup(cancel)
	h.addr = serveTrap(t, ctx, h.trap)
	return h
}

func startDocker(t *testing.T) *stubHarness {
	return startStub(t, "docker", func(c *config.Config, l *slog.Logger, m *metrics.Metrics, lim *Limiter, r Reporter) Trap {
		return NewDocker(c, l, m, lim, r)
	})
}

func startKubernetes(t *testing.T) *stubHarness {
	return startStub(t, "kubernetes", func(c *config.Config, l *slog.Logger, m *metrics.Metrics, lim *Limiter, r Reporter) Trap {
		return NewKubernetes(c, l, m, lim, r)
	})
}

type stubResult struct {
	status int
	body   string
	header http.Header
}

// stubDo sends one request on a fresh connection.
func stubDo(t *testing.T, addr, method, path string, headers map[string]string, body string) stubResult {
	t.Helper()
	req, err := http.NewRequest(method, "http://"+addr+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return stubResult{status: resp.StatusCode, body: string(b), header: resp.Header}
}

// waitClass waits for the session outcome. A probe is a single event emitted at
// session end; an attack is the first attack event.
func (h *stubHarness) waitClass(t *testing.T, attack bool) alert.Event {
	t.Helper()
	if !attack {
		evs := h.sink.waitEvents(t, func(e []alert.Event) bool { return hasClass(e, alert.ClassProbe) })
		if len(evs) != 1 || evs[0].Class != alert.ClassProbe {
			t.Fatalf("want a single probe event, got %+v", evs)
		}
		return evs[0]
	}
	return waitAttack(t, h.sink)
}

// assertStopClosesConnections opens a keep-alive connection, stops the trap
// (twice) and expects the connection to be closed.
func assertStopClosesConnections(t *testing.T, h *stubHarness, request string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", h.addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.trap.Stop(stopCtx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := h.trap.Stop(stopCtx); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
	var one [1]byte
	if _, err := conn.Read(one[:]); err == nil {
		t.Error("connection still open after Stop")
	}
}
