package trap

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

func vncTestConfig(t *testing.T) *config.Config {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	return &config.Config{
		Addrs:          map[string]string{"vnc": addr},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}
}

func TestVNCTrapHandshake(t *testing.T) {
	cfg := vncTestConfig(t)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewVNC(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = trap.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", cfg.TrapAddr("vnc"), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Read server RFB version
	var serverVersion [12]byte
	if _, err := io.ReadFull(conn, serverVersion[:]); err != nil {
		t.Fatal(err)
	}
	if string(serverVersion[:]) != "RFB 003.008\n" {
		t.Errorf("server version = %q, want %q", serverVersion, "RFB 003.008\n")
	}

	// Send client RFB version
	if _, err := conn.Write([]byte("RFB 003.008\n")); err != nil {
		t.Fatal(err)
	}

	// Read security types
	var secTypes [2]byte
	if _, err := io.ReadFull(conn, secTypes[:]); err != nil {
		t.Fatal(err)
	}
	if secTypes[0] != 1 {
		t.Errorf("security type count = %d, want 1", secTypes[0])
	}
	if secTypes[1] != 2 {
		t.Errorf("security type = %d, want 2 (VNC Auth)", secTypes[1])
	}

	// Send security type selection
	if _, err := conn.Write([]byte{2}); err != nil {
		t.Fatal(err)
	}

	// Read 16-byte challenge
	var challenge [16]byte
	if _, err := io.ReadFull(conn, challenge[:]); err != nil {
		t.Fatal(err)
	}

	// Send fake 16-byte response
	fakeResponse := make([]byte, 16)
	for i := range fakeResponse {
		fakeResponse[i] = byte(i)
	}
	if _, err := conn.Write(fakeResponse); err != nil {
		t.Fatal(err)
	}

	// Read SecurityResult (uint32 = 1 for failure)
	var result [4]byte
	if _, err := io.ReadFull(conn, result[:]); err != nil {
		t.Fatal(err)
	}
	secResult := binary.BigEndian.Uint32(result[:])
	if secResult != 1 {
		t.Errorf("security result = %d, want 1 (failed)", secResult)
	}

	// Read reason length
	var reasonLen [4]byte
	if _, err := io.ReadFull(conn, reasonLen[:]); err != nil {
		t.Fatal(err)
	}
	rLen := binary.BigEndian.Uint32(reasonLen[:])

	// Read reason string
	reason := make([]byte, rLen)
	if _, err := io.ReadFull(conn, reason); err != nil {
		t.Fatal(err)
	}
	if string(reason) != "Authentication failed" {
		t.Errorf("reason = %q, want %q", reason, "Authentication failed")
	}

	cancel()
	_ = trap.Stop(context.Background())
}

func TestVNCTrapVersion(t *testing.T) {
	cfg := vncTestConfig(t)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewVNC(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = trap.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", cfg.TrapAddr("vnc"), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	var serverVersion [12]byte
	if _, err := io.ReadFull(conn, serverVersion[:]); err != nil {
		t.Fatal(err)
	}
	if string(serverVersion[:]) != "RFB 003.008\n" {
		t.Errorf("server version = %q, want %q", serverVersion, "RFB 003.008\n")
	}

	cancel()
	_ = trap.Stop(context.Background())
}
