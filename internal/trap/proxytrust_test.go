package trap

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

// otherPeers trusts a range that does not contain the loopback test clients.
func otherPeers() *config.ProxyTrust {
	return config.NewProxyTrust([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, false)
}

func v2Header(cmd, family byte, body []byte) []byte {
	hdr := make([]byte, 16)
	copy(hdr, v2Signature)
	hdr[12], hdr[13] = cmd, family
	binary.BigEndian.PutUint16(hdr[14:16], uint16(len(body)))
	return append(hdr, body...)
}

func v2TCP4Body(src string, port uint16) []byte {
	b := make([]byte, 12)
	copy(b[0:4], net.ParseIP(src).To4())
	copy(b[4:8], net.ParseIP("1.1.1.1").To4())
	binary.BigEndian.PutUint16(b[8:10], port)
	binary.BigEndian.PutUint16(b[10:12], 80)
	return b
}

func proxyHeaders() map[string][]byte {
	return map[string][]byte{
		"v1 forged":    []byte("PROXY TCP4 8.8.8.8 1.1.1.1 40000 80\r\n"),
		"v2 forged":    v2Header(0x21, 0x11, v2TCP4Body("8.8.8.8", 40000)),
		"v2 local":     v2Header(0x20, 0x00, nil),
		"v1 unknown":   []byte("PROXY UNKNOWN\r\n"),
		"plain bytes":  []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		"garbage":      []byte("\x00\x01\x02\x03"),
		"empty header": []byte("\r\n"),
	}
}

func TestProxyUntrustedPeerDroppedBeforeHeader(t *testing.T) {
	for name, data := range proxyHeaders() {
		t.Run(name, func(t *testing.T) {
			logs := &syncBuffer{}
			m := metrics.New(prometheus.NewRegistry(), "test")
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			pl := newProxyListener(ln, newJSONLogger(logs), m, "test", otherPeers())
			defer pl.Close()
			accepted := make(chan net.Conn, 1)
			go func() {
				if c, err := pl.Accept(); err == nil {
					accepted <- c
				}
			}()

			c, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_, _ = c.Write(data)

			expectClosed(t, c, 2*time.Second)
			waitFor(t, func() bool { return proxyDropped(t, m, "test") == 1 })
			select {
			case got := <-accepted:
				t.Fatalf("untrusted peer was handed on: %v", got.RemoteAddr())
			case <-time.After(100 * time.Millisecond):
			}
			if len(pl.sem) != 0 {
				t.Error("an untrusted peer must not take a handshake slot")
			}
			out := logs.String()
			if strings.Contains(out, "8.8.8.8") || strings.Contains(out, "127.0.0.1") {
				t.Errorf("dropping an untrusted peer must not log addresses: %s", out)
			}
			for _, lvl := range []string{`"level":"INFO"`, `"level":"WARN"`, `"level":"ERROR"`} {
				if strings.Contains(out, lvl) {
					t.Errorf("untrusted drops are logged at debug only: %s", out)
				}
			}
		})
	}
}

func TestProxyUntrustedDoesNotConsumeHandshakeSlots(t *testing.T) {
	old := maxPendingHandshakes
	maxPendingHandshakes = 2
	defer func() { maxPendingHandshakes = old }()

	m := metrics.New(prometheus.NewRegistry(), "test")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pl := newProxyListener(ln, nil, m, "test", otherPeers())
	defer pl.Close()
	go func() { _, _ = pl.Accept() }()

	for i := 0; i < 10; i++ {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}
	waitFor(t, func() bool { return proxyDropped(t, m, "test") == 10 })
	if len(pl.sem) != 0 {
		t.Errorf("handshake slots in use = %d, want 0", len(pl.sem))
	}
}

func TestProxyTrustedPeerHeaders(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want string // host of RemoteAddr
	}{
		{"v1 tcp4", []byte("PROXY TCP4 8.8.8.8 1.1.1.1 40000 80\r\n"), "8.8.8.8"},
		{"v1 tcp6", []byte("PROXY TCP6 2606:4700:4700::1111 ::1 40000 80\r\n"), "2606:4700:4700::1111"},
		{"v2 tcp4", v2Header(0x21, 0x11, v2TCP4Body("8.8.8.8", 40000)), "8.8.8.8"},
		{"v1 unknown keeps proxy address", []byte("PROXY UNKNOWN\r\n"), "127.0.0.1"},
		{"v2 local keeps proxy address", v2Header(0x20, 0x00, nil), "127.0.0.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pl, m, addr := newTestProxyListener(t)
			accepted := make(chan net.Conn, 1)
			go func() {
				if c, err := pl.Accept(); err == nil {
					accepted <- c
				}
			}()
			c, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_, _ = c.Write(append(append([]byte(nil), tc.data...), "payload"...))
			select {
			case got := <-accepted:
				defer got.Close()
				host, _ := ParseAddr(got.RemoteAddr().String())
				if host != tc.want {
					t.Errorf("RemoteAddr host = %q, want %q", host, tc.want)
				}
				buf := make([]byte, 7)
				if _, err := io.ReadFull(got, buf); err != nil || string(buf) != "payload" {
					t.Errorf("payload = %q, %v", buf, err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("trusted peer was not accepted")
			}
			if n := proxyDropped(t, m, "test"); n != 0 {
				t.Errorf("dropped = %v, want 0", n)
			}
		})
	}
}

func TestProxyTrustedPeerWithoutHeaderStillDropped(t *testing.T) {
	pl, m, addr := newTestProxyListener(t)
	go func() { _, _ = pl.Accept() }()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	expectClosed(t, c, 2*time.Second)
	waitFor(t, func() bool { return proxyDropped(t, m, "test") == 1 })
}

func TestProxyTrustAnyAcceptsEveryPeer(t *testing.T) {
	m := metrics.New(prometheus.NewRegistry(), "test")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pl := newProxyListener(ln, nil, m, "test", config.NewProxyTrust(nil, true))
	defer pl.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		if c, err := pl.Accept(); err == nil {
			accepted <- c
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("PROXY TCP4 8.8.8.8 1.1.1.1 40000 80\r\n"))
	select {
	case got := <-accepted:
		got.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("any must trust the peer")
	}
}

func TestProxyNilTrustFailsClosed(t *testing.T) {
	m := metrics.New(prometheus.NewRegistry(), "test")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pl := newProxyListener(ln, nil, m, "test", nil)
	defer pl.Close()
	go func() { _, _ = pl.Accept() }()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("PROXY TCP4 8.8.8.8 1.1.1.1 40000 80\r\n"))
	expectClosed(t, c, 2*time.Second)
	waitFor(t, func() bool { return proxyDropped(t, m, "test") == 1 })
}

func TestProxyUntrustedNoGoroutineLeak(t *testing.T) {
	before := runtime.NumGoroutine()
	m := metrics.New(prometheus.NewRegistry(), "test")
	ml, err := ListenMultiTCP(context.Background(), []string{"127.0.0.1:0"}, otherPeers(), nil, m, "test")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = ml.Accept() }()
	for i := 0; i < 50; i++ {
		c, err := net.Dial("tcp", ml.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte("PROXY TCP4 8.8.8.8 1.1.1.1 40000 80\r\n"))
		c.Close()
	}
	waitFor(t, func() bool { return proxyDropped(t, m, "test") == 50 })
	_ = ml.Close()
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > before+2 {
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<16)
			t.Fatalf("goroutines: %d after close, %d before\n%s", runtime.NumGoroutine(), before, buf[:runtime.Stack(buf, true)])
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// An HTTP based trap shares the listener: a forged header from an untrusted
// peer is dropped without a session or an alert.
func TestHTTPTrapDropsUntrustedProxyPeer(t *testing.T) {
	cfg := httpTestConfig(t)
	cfg.ProxyProtocol = true
	cfg.ProxyTrusted = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	rec := &recordingAlerter{}
	logs := &syncBuffer{}
	m := metrics.New(prometheus.NewRegistry(), "test")
	tr := NewHTTP(cfg, newJSONLogger(logs), m, NewLimiter(cfg.MaxSessions, cfg.MaxPerIP), rec)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := serveTrap(t, ctx, tr)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprint(c, "PROXY TCP4 8.8.8.8 1.1.1.1 40000 80\r\nPOST /admin HTTP/1.1\r\nHost: x\r\nContent-Length: 21\r\n\r\nusername=a&password=b")
	expectClosed(t, c, 2*time.Second)
	waitFor(t, func() bool { return proxyDropped(t, m, "http") == 1 })
	if n := len(rec.snapshot()); n != 0 {
		t.Errorf("alerts = %d, want 0", n)
	}
	if strings.Contains(logs.String(), "8.8.8.8") {
		t.Errorf("claimed address was logged: %s", logs.String())
	}
}

// End to end with the real Sensor and CrowdSec sink: a forged header from an
// untrusted peer (127.0.0.1) yields no alert, while a header from the trusted
// proxy (127.0.0.2) does.
func TestEndToEndForgedProxyHeaderNoAlert(t *testing.T) {
	lapi := &fakeLAPI{}
	srv := httptest.NewServer(lapi.handler())
	defer srv.Close()

	logger := newJSONLogger(&syncBuffer{})
	m := metrics.New(prometheus.NewRegistry(), "test")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sink, err := alert.NewCrowdSec(ctx, alert.CrowdSecConfig{
		URL: srv.URL, MachineID: "ran", Password: "secret", BatchInterval: 50 * time.Millisecond, BatchSize: 1,
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
		ProxyTrusted:   []netip.Prefix{netip.MustParsePrefix("127.0.0.2/32")},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
		MaxAuthRetries: 1,
	}
	tr := NewTelnet(cfg, logger, m, NewLimiter(cfg.MaxSessions, cfg.MaxPerIP), sensor)
	addr := serveTrap(t, ctx, tr)

	forged, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer forged.Close()
	_ = forged.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(forged, "PROXY TCP4 8.8.8.8 127.0.0.1 40000 23\r\nroot\r\nsecret\r\n")
	_, _ = io.Copy(io.Discard, bufio.NewReader(forged))
	waitFor(t, func() bool { return proxyDropped(t, m, "telnet") == 1 })

	d := net.Dialer{Timeout: 2 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}
	good, err := d.Dial("tcp", addr)
	if err != nil {
		t.Skipf("cannot bind 127.0.0.2 as a second source address: %v", err)
	}
	defer good.Close()
	_ = good.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(good, "PROXY TCP4 9.9.9.9 127.0.0.1 40000 23\r\nroot\r\nsecret\r\n")
	_, _ = io.Copy(io.Discard, bufio.NewReader(good))

	// The forged connection was dropped and counted before the trusted one was
	// opened, so no further alert can arrive from it.
	waitFor(t, func() bool { return lapi.acceptedCount() == 1 })

	lapi.mu.Lock()
	defer lapi.mu.Unlock()
	seen := map[string]bool{}
	for _, batch := range lapi.accepted {
		for _, a := range batch {
			checkCrowdSecAlert(t, a, seen)
		}
	}
	if len(seen) != 1 || !seen["9.9.9.9"] || seen["8.8.8.8"] {
		t.Errorf("alerted sources = %v, want only 9.9.9.9", seen)
	}
}

// fakePeerConn reports a chosen remote address; the other end stays silent.
type fakePeerConn struct {
	net.Conn
	remote net.Addr
}

func (c *fakePeerConn) RemoteAddr() net.Addr { return c.remote }

// fakePeerListener hands out queued connections, then blocks until closed.
type fakePeerListener struct {
	conns  chan net.Conn
	closed chan struct{}
}

func (l *fakePeerListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *fakePeerListener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}
	return nil
}

func (l *fakePeerListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}
}

// The trust check runs before a handshake slot is taken. With the only slot
// held by a trusted silent peer, an untrusted peer must still be rejected as
// untrusted_peer and a second trusted peer as handshake_limit. If the check
// moved behind the semaphore, the untrusted peer would show up as
// handshake_limit. Both reasons share one metric; only the debug log tells
// them apart.
func TestProxyTrustCheckPrecedesHandshakeLimit(t *testing.T) {
	// Only the slot count is changed: the holder goroutine may outlive the test
	// and reads proxyHeaderTimeout, so that variable is left alone.
	oldMax := maxPendingHandshakes
	maxPendingHandshakes = 1
	defer func() { maxPendingHandshakes = oldMax }()

	peer := func(ip string) (net.Conn, net.Conn) {
		server, client := net.Pipe()
		t.Cleanup(func() { server.Close(); client.Close() })
		addr := &net.TCPAddr{IP: net.ParseIP(ip), Port: 40000}
		return &fakePeerConn{Conn: server, remote: addr}, client
	}
	holder, _ := peer("10.0.0.1")   // trusted, takes the only slot and stays silent
	overflow, _ := peer("10.0.0.2") // trusted, no slot left
	untrusted, _ := peer("8.8.8.8") // untrusted, must not be judged by the slot

	logs := &syncBuffer{}
	m := metrics.New(prometheus.NewRegistry(), "test")
	fl := &fakePeerListener{conns: make(chan net.Conn, 3), closed: make(chan struct{})}
	fl.conns <- holder
	fl.conns <- overflow
	fl.conns <- untrusted
	pl := newProxyListener(fl, newJSONLogger(logs), m, "test", otherPeers())
	defer pl.Close()
	go func() { _, _ = pl.Accept() }()

	waitFor(t, func() bool { return proxyDropped(t, m, "test") == 2 })
	out := logs.String()
	if got := strings.Count(out, `"reason":"untrusted_peer"`); got != 1 {
		t.Errorf("untrusted_peer drops = %d, want 1: %s", got, out)
	}
	if got := strings.Count(out, `"reason":"handshake_limit"`); got != 1 {
		t.Errorf("handshake_limit drops = %d, want 1: %s", got, out)
	}
	if len(pl.sem) != 1 {
		t.Errorf("handshake slots in use = %d, want 1 (the trusted holder)", len(pl.sem))
	}
	if strings.Contains(out, "8.8.8.8") {
		t.Errorf("drop log must not contain addresses: %s", out)
	}
}
