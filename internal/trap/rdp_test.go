package trap

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

func rdpTestConfig(t *testing.T) *config.Config {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	return &config.Config{
		Addrs:          map[string]string{"rdp": addr},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}
}

func buildRDPConnectionRequest(cookie string) []byte {
	// X.224 CR payload: length indicator(1) + type 0xE0(1) + dst-ref(2) + src-ref(2) + class(1) + cookie
	var cookieBytes []byte
	if cookie != "" {
		cookieBytes = []byte("Cookie: mstshash=" + cookie + "\r\n")
	}

	x224Len := 6 + len(cookieBytes)
	tpktLen := 4 + 1 + x224Len // TPKT header + length indicator byte + x224 payload

	buf := make([]byte, tpktLen)
	// TPKT header
	buf[0] = 3
	buf[1] = 0
	binary.BigEndian.PutUint16(buf[2:4], uint16(tpktLen))

	// X.224 Connection Request
	buf[4] = byte(x224Len) // length indicator
	buf[5] = 0xE0          // type: CR
	// dst-ref(2), src-ref(2), class(1) = zeros
	copy(buf[11:], cookieBytes)

	return buf
}

func TestRDPTrapWithCookie(t *testing.T) {
	cfg := rdpTestConfig(t)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewRDP(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = trap.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", cfg.TrapAddr("rdp"), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Send RDP Connection Request with cookie
	req := buildRDPConnectionRequest("administrator")
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}

	// Read response
	var tpkt [4]byte
	if _, err := conn.Read(tpkt[:]); err != nil {
		t.Fatal(err)
	}
	if tpkt[0] != 3 {
		t.Errorf("TPKT version = %d, want 3", tpkt[0])
	}

	respLen := int(binary.BigEndian.Uint16(tpkt[2:4]))
	if respLen != 19 {
		t.Errorf("response length = %d, want 19", respLen)
	}

	resp := make([]byte, respLen-4)
	if _, err := conn.Read(resp); err != nil {
		t.Fatal(err)
	}

	// Verify X.224 CC type
	if resp[1] != 0xD0 {
		t.Errorf("X.224 type = 0x%02X, want 0xD0", resp[1])
	}

	// Verify RDP Negotiation Failure type
	if resp[7] != 0x03 {
		t.Errorf("neg failure type = 0x%02X, want 0x03", resp[7])
	}

	// Verify failure code (SSL_REQUIRED_BY_SERVER = 2)
	failureCode := binary.LittleEndian.Uint32(resp[11:15])
	if failureCode != 2 {
		t.Errorf("failure code = %d, want 2", failureCode)
	}

	cancel()
	_ = trap.Stop(context.Background())
}

func TestRDPTrapNoCookie(t *testing.T) {
	cfg := rdpTestConfig(t)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewRDP(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = trap.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", cfg.TrapAddr("rdp"), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	req := buildRDPConnectionRequest("")
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}

	var tpkt [4]byte
	if _, err := conn.Read(tpkt[:]); err != nil {
		t.Fatal(err)
	}
	if tpkt[0] != 3 {
		t.Errorf("TPKT version = %d, want 3", tpkt[0])
	}

	cancel()
	_ = trap.Stop(context.Background())
}
