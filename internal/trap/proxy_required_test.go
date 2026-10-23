package trap

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/st0o0/ran/internal/metrics"
)

func proxyDropped(t *testing.T, m *metrics.Metrics, protocol string) float64 {
	t.Helper()
	var out dto.Metric
	if err := m.ProxyDropped.WithLabelValues(protocol).Write(&out); err != nil {
		t.Fatal(err)
	}
	return out.GetCounter().GetValue()
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// expectClosed fails if c is still open (read times out) or delivers data.
func expectClosed(t *testing.T, c net.Conn, wait time.Duration) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(wait))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("expected the connection to be closed, got data")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Error("connection was left open")
	}
}

func newTestProxyListener(t *testing.T) (*proxyListener, *metrics.Metrics, string) {
	t.Helper()
	m := metrics.New(prometheus.NewRegistry(), "test")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pl := newProxyListener(ln, nil, m, "test")
	t.Cleanup(func() { _ = pl.Close() })
	return pl, m, ln.Addr().String()
}

func TestProxyHeaderDeadlineDropsSilentPeer(t *testing.T) {
	old := proxyHeaderTimeout
	proxyHeaderTimeout = 100 * time.Millisecond
	defer func() { proxyHeaderTimeout = old }()

	ml, addr := dialProxyListener(t, true)
	silent, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()

	// The silent peer is closed once the deadline hits, not handed on.
	expectClosed(t, silent, 2*time.Second)

	// A peer with a valid header is still accepted afterwards.
	good, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer good.Close()
	_, _ = good.Write([]byte("PROXY TCP4 192.0.2.5 192.0.2.6 1111 2222\r\n"))
	done := make(chan net.Conn, 1)
	go func() {
		c, _ := ml.Accept()
		done <- c
	}()
	select {
	case c := <-done:
		if c == nil || !strings.HasPrefix(c.RemoteAddr().String(), "192.0.2.5") {
			t.Fatalf("unexpected conn %v", c)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("valid peer was not accepted after a dropped silent peer")
	}
}

func TestProxyNonProxyBytesDropped(t *testing.T) {
	pl, m, addr := newTestProxyListener(t)
	go func() { _, _ = pl.Accept() }()

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))

	expectClosed(t, c, 2*time.Second)
	waitFor(t, func() bool { return proxyDropped(t, m, "test") == 1 })
}

func TestProxyHandshakeFloodIsBounded(t *testing.T) {
	oldMax := maxPendingHandshakes
	maxPendingHandshakes = 8
	defer func() { maxPendingHandshakes = oldMax }()

	pl, m, addr := newTestProxyListener(t)
	go func() { _, _ = pl.Accept() }() // starts the accept loop

	const total = 20
	conns := make([]net.Conn, 0, total)
	for i := 0; i < total; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		conns = append(conns, c)
	}

	// Only maxPendingHandshakes handshakes are pending; the rest are shed.
	waitFor(t, func() bool { return proxyDropped(t, m, "test") == total-8 })
	if got := len(pl.sem); got != 8 {
		t.Errorf("pending handshakes = %d, want 8", got)
	}
	closed := 0
	for _, c := range conns {
		_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if _, err := c.Read(make([]byte, 1)); err != nil {
			if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
				closed++
			}
		}
	}
	if closed != total-8 {
		t.Errorf("%d connections closed immediately, want %d", closed, total-8)
	}
}

func TestProxyStalledConsumerClosesConnections(t *testing.T) {
	old := proxyHandoffTimeout
	proxyHandoffTimeout = 100 * time.Millisecond
	defer func() { proxyHandoffTimeout = old }()

	pl, m, addr := newTestProxyListener(t)
	// Start the accept loop but never call Accept: the consumer is stalled.
	pl.startOnce.Do(func() { go pl.acceptLoop() })

	var conns []net.Conn
	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_, _ = c.Write([]byte("PROXY TCP4 192.0.2.5 192.0.2.6 1111 2222\r\n"))
		conns = append(conns, c)
	}

	waitFor(t, func() bool { return proxyDropped(t, m, "test") == 3 })
	waitFor(t, func() bool { return len(pl.sem) == 0 })
	for _, c := range conns {
		expectClosed(t, c, 2*time.Second)
	}
}

func TestParseV2Validation(t *testing.T) {
	build := func(verCmd, family byte, addrLen int, body []byte) []byte {
		hdr := make([]byte, 16)
		copy(hdr, v2Signature)
		hdr[12], hdr[13] = verCmd, family
		binary.BigEndian.PutUint16(hdr[14:16], uint16(addrLen))
		return append(hdr, body...)
	}
	tcp4 := make([]byte, 12)
	copy(tcp4[0:4], []byte{192, 0, 2, 1})
	binary.BigEndian.PutUint16(tcp4[8:10], 1234)

	cases := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{"valid proxy tcp4", build(0x21, 0x11, 12, tcp4), false},
		{"valid local", build(0x20, 0x00, 0, nil), false},
		{"version 1", build(0x11, 0x11, 12, tcp4), true},
		{"version 0", build(0x01, 0x11, 12, tcp4), true},
		{"version 3", build(0x31, 0x11, 12, tcp4), true},
		{"max addr len", build(0x20, 0x00, 536, make([]byte, 536)), false},
		{"addr len over cap", build(0x20, 0x00, 537, make([]byte, 537)), true},
		{"addr len 65535 without data", build(0x21, 0x11, 65535, nil), true},
		{"tcp4 too short", build(0x21, 0x11, 4, tcp4[:4]), true},
		{"unknown command", build(0x22, 0x11, 12, tcp4), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseV2(bufio.NewReader(bytes.NewReader(tc.data)))
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

type panicListener struct {
	net.Listener
	calls atomic.Int64
}

func (p *panicListener) Accept() (net.Conn, error) {
	p.calls.Add(1)
	panic("accept boom")
}

func (p *panicListener) Close() error { return nil }

func TestAcceptPanicBacksOff(t *testing.T) {
	ln := &panicListener{}
	m := metrics.New(prometheus.NewRegistry(), "test")
	ml := newMultiListener([]net.Listener{ln}, newJSONLogger(io.Discard), m, "test")

	time.Sleep(400 * time.Millisecond)
	closed := make(chan struct{})
	go func() {
		_ = ml.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close hung while Accept keeps panicking")
	}
	// 10ms doubling: about 6 attempts in 400ms. A spin would make thousands.
	if calls := ln.calls.Load(); calls < 2 || calls > 20 {
		t.Errorf("Accept called %d times in 400ms, want a small backed-off number", calls)
	}
	if got := panicCount(t, m, "test"); got < 2 {
		t.Errorf("panics counted = %v, want at least 2", got)
	}
}
