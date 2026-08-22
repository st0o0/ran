package trap

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

func TestADBTrapCNXN(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := &config.Config{
		Addrs:          map[string]string{"adb": addr},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := metrics.New(prometheus.NewRegistry(), "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)
	alerter := alert.NoopAlerter{}

	tr := NewADB(cfg, logger, m, limiter, alerter)

	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	go func() { close(started); _ = tr.Start(ctx) }()
	<-started
	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	identity := []byte("host::features=shell_v2")
	hdr := make([]byte, adbHdrSize)
	binary.LittleEndian.PutUint32(hdr[0:4], adbCmdCNXN)
	binary.LittleEndian.PutUint32(hdr[4:8], 0x01000000) // version
	binary.LittleEndian.PutUint32(hdr[8:12], 4096)       // max data
	binary.LittleEndian.PutUint32(hdr[12:16], uint32(len(identity)))

	_, err = conn.Write(append(hdr, identity...))
	if err != nil {
		t.Fatal(err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, 256)
	n, err := conn.Read(resp)
	if err != nil {
		t.Fatal(err)
	}

	if n < adbHdrSize {
		t.Fatalf("response too short: %d bytes", n)
	}

	respCmd := binary.LittleEndian.Uint32(resp[0:4])
	if respCmd != adbCmdAUTH {
		t.Errorf("response command = 0x%08x, want AUTH (0x%08x)", respCmd, adbCmdAUTH)
	}

	authType := binary.LittleEndian.Uint32(resp[4:8])
	if authType != 1 {
		t.Errorf("AUTH type = %d, want 1 (TOKEN)", authType)
	}

	tokenLen := binary.LittleEndian.Uint32(resp[12:16])
	if tokenLen != 20 {
		t.Errorf("token length = %d, want 20", tokenLen)
	}

	cancel()
	_ = tr.Stop(context.Background())
}

func TestADBTrapMalformed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := &config.Config{
		Addrs:          map[string]string{"adb": addr},
		SessionTimeout: 2 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := metrics.New(prometheus.NewRegistry(), "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)
	alerter := alert.NoopAlerter{}

	tr := NewADB(cfg, logger, m, limiter, alerter)

	ctx, cancel := context.WithCancel(context.Background())
	startDone := make(chan struct{})
	go func() { _ = tr.Start(ctx); close(startDone) }()
	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}

	_, _ = conn.Write([]byte("short"))
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 64)
	_, err = conn.Read(buf)
	if err == nil {
		t.Error("expected no response for malformed data")
	}
	conn.Close()

	cancel()
	<-startDone
	_ = tr.Stop(context.Background())
}
