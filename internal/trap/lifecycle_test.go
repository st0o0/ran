package trap

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

func lifecycleConfig(timeout time.Duration) *config.Config {
	return &config.Config{
		Addrs:          map[string]string{"telnet": "127.0.0.1:0"},
		PerProto:       make(map[string]config.ProtoConfig),
		SessionTimeout: timeout,
		MaxSessions:    1000,
		MaxPerIP:       1000,
		MaxAuthRetries: 3,
	}
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newLifecycleTelnet(timeout time.Duration) *TelnetTrap {
	cfg := lifecycleConfig(timeout)
	m := metrics.New(prometheus.NewRegistry(), "test")
	return NewTelnet(cfg, quietLogger(), m, NewLimiter(cfg.MaxSessions, cfg.MaxPerIP), alert.NoopAlerter{})
}

// expectEOF fails unless the peer closes c within wait.
func expectEOF(t *testing.T, c net.Conn, wait time.Duration) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(wait))
	if _, err := io.Copy(io.Discard, c); err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatal("connection was not closed in time")
		}
	}
}

func TestStopClosesIdleClientPromptly(t *testing.T) {
	tr := newLifecycleTelnet(30 * time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := serveTrap(t, ctx, tr)

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// The prompt proves the session is live and idle (waiting for input).
	if _, err := bufio.NewReader(conn).ReadString(':'); err != nil {
		t.Fatal(err)
	}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	start := time.Now()
	if err := tr.Stop(stopCtx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("Stop took %v with an idle client and a 30s session timeout, want < 1s", d)
	}
	expectEOF(t, conn, time.Second)
}

func TestStartContextCancelClosesIdleClient(t *testing.T) {
	tr := newLifecycleTelnet(30 * time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := serveTrap(t, ctx, tr)

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := bufio.NewReader(conn).ReadString(':'); err != nil {
		t.Fatal(err)
	}

	cancel()
	expectEOF(t, conn, time.Second)
}

// stuckServer returns a server whose handler ignores the closed connection and
// blocks until release is closed.
func stuckServer(t *testing.T) (srv *tcpServer, addr string, entered <-chan struct{}, release func()) {
	t.Helper()
	cfg := lifecycleConfig(30 * time.Second)
	m := metrics.New(prometheus.NewRegistry(), "test")
	in := make(chan struct{}, 16)
	gate := make(chan struct{})
	srv = newTCPServer("telnet", cfg, quietLogger(), m, NewLimiter(cfg.MaxSessions, cfg.MaxPerIP), alert.NoopAlerter{},
		func(ctx context.Context, conn net.Conn, sess *Session) {
			in <- struct{}{}
			<-gate
		})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	addr = serveTrap(t, ctx, srv)
	var once sync.Once
	release = func() { once.Do(func() { close(gate) }) }
	// Registered after serveTrap, so it runs before the trap's own Stop.
	t.Cleanup(release)
	return srv, addr, in, release
}

func TestStopHonoursContextDeadline(t *testing.T) {
	srv, addr, entered, release := stuckServer(t)

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not start")
	}

	stopCtx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = srv.Stop(stopCtx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Stop = %v, want context.DeadlineExceeded while a worker is stuck", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("Stop took %v, want to return at the 150ms deadline", d)
	}

	release()
	okCtx, okCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer okCancel()
	if err := srv.Stop(okCtx); err != nil {
		t.Errorf("Stop after the worker finished = %v, want nil", err)
	}
}

func TestStopIsIdempotent(t *testing.T) {
	tr := newLifecycleTelnet(5 * time.Second)

	// Stop before Start is a no-op and makes a later Start return at once.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for range 3 {
		if err := tr.Stop(ctx); err != nil {
			t.Fatalf("Stop before Start: %v", err)
		}
	}
	done := make(chan error, 1)
	go func() { done <- tr.Start(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Start after Stop = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start after Stop did not return")
	}

	// Repeated Stop on a running trap.
	running := newLifecycleTelnet(5 * time.Second)
	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	serveTrap(t, runCtx, running)
	for range 3 {
		if err := running.Stop(ctx); err != nil {
			t.Fatalf("repeated Stop: %v", err)
		}
	}
}

func TestRapidStartStopDoesNotRaceWaitGroup(t *testing.T) {
	for i := 0; i < 100; i++ {
		tr := newLifecycleTelnet(5 * time.Second)
		ctx, cancel := context.WithCancel(context.Background())
		startErr := make(chan error, 1)
		go func() { startErr <- tr.Start(ctx) }()

		// Clients hammer the trap while it shuts down; errors are expected.
		var clients sync.WaitGroup
		if i%2 == 0 {
			select {
			case <-tr.Ready():
				addr := tr.Addr().String()
				for range 4 {
					clients.Add(1)
					go func() {
						defer clients.Done()
						c, err := net.DialTimeout("tcp", addr, time.Second)
						if err == nil {
							_, _ = c.Write([]byte("x\r\n"))
							c.Close()
						}
					}()
				}
			case <-time.After(2 * time.Second):
				t.Fatal("trap did not start")
			}
		}

		stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
		if err := tr.Stop(stopCtx); err != nil {
			t.Fatalf("iteration %d: Stop: %v", i, err)
		}
		stopCancel()
		select {
		case err := <-startErr:
			if err != nil {
				t.Fatalf("iteration %d: Start: %v", i, err)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("iteration %d: Start did not return after Stop", i)
		}
		clients.Wait()
		cancel()
	}
}

func rejectedCount(t *testing.T, m *metrics.Metrics, proto string) float64 {
	t.Helper()
	var out dto.Metric
	if err := m.SessionsRejected.WithLabelValues(proto).Write(&out); err != nil {
		t.Fatal(err)
	}
	return out.GetCounter().GetValue()
}

// TestLimiterAcquiredBeforeGoroutine floods a trap far beyond its limit. The
// limiter slot is taken before the connection goroutine exists, so at most
// `limit` handlers ever run and the rest are rejected without a goroutine.
func TestLimiterAcquiredBeforeGoroutine(t *testing.T) {
	const limit, flood = 5, 300

	cfg := lifecycleConfig(30 * time.Second)
	m := metrics.New(prometheus.NewRegistry(), "test")
	var running, peak atomic.Int32
	gate := make(chan struct{})
	srv := newTCPServer("telnet", cfg, quietLogger(), m, NewLimiter(limit, limit), alert.NoopAlerter{},
		func(ctx context.Context, conn net.Conn, sess *Session) {
			n := running.Add(1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			defer running.Add(-1)
			select {
			case <-gate:
			case <-ctx.Done():
			}
		})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := serveTrap(t, ctx, srv)
	t.Cleanup(func() { close(gate) })

	base := runtime.NumGoroutine()
	conns := make([]net.Conn, 0, flood)
	for range flood {
		c, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()

	waitFor(t, func() bool { return rejectedCount(t, m, "telnet") == flood-limit })
	if got := peak.Load(); got > limit {
		t.Errorf("peak concurrent handlers = %d, want <= %d", got, limit)
	}
	// Each admitted connection owns one goroutine; rejected ones own none.
	if grew := runtime.NumGoroutine() - base; grew > limit+10 {
		t.Errorf("goroutines grew by %d during a flood of %d with limit %d", grew, flood, limit)
	}
}

func TestNoGoroutineLeakAfterStop(t *testing.T) {
	base := runtime.NumGoroutine()

	tr := newLifecycleTelnet(30 * time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	startErr := make(chan error, 1)
	go func() { startErr <- tr.Start(ctx) }()
	<-tr.Ready()
	addr := tr.Addr().String()

	var conns []net.Conn
	for range 20 {
		c, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	for _, c := range conns {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := bufio.NewReader(c).ReadString(':'); err != nil {
			t.Fatal(err)
		}
	}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopCancel()
	if err := tr.Stop(stopCtx); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-startErr; err != nil {
		t.Logf("trap start returned: %v", err)
	}
	for _, c := range conns {
		c.Close()
	}

	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > base+3 {
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<16)
			buf = buf[:runtime.Stack(buf, true)]
			t.Fatalf("goroutines: %d after stop, %d before\n%s", runtime.NumGoroutine(), base, buf)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

type blockingPacketHandler struct{ gate chan struct{} }

func (h *blockingPacketHandler) HandlePacket(ctx context.Context, sess *Session, data []byte, respond func([]byte)) {
	<-h.gate
}

func TestUDPStopHonoursContextDeadline(t *testing.T) {
	m := metrics.New(prometheus.NewRegistry(), "test")
	h := &blockingPacketHandler{gate: make(chan struct{})}
	tr := NewUDP("dns", []string{"127.0.0.1:0"}, quietLogger(), m, NewLimiter(10, 10), newUDPRateLimiter(&config.Config{}), h)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := serveTrap(t, ctx, tr)
	t.Cleanup(func() { close(h.gate) })

	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("x"))
	// Give the read loop time to hand the packet to the blocked handler.
	time.Sleep(100 * time.Millisecond)

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer stopCancel()
	start := time.Now()
	if err := tr.Stop(stopCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Stop = %v, want context.DeadlineExceeded while a handler is stuck", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("Stop took %v, want to return at the deadline", d)
	}
}
