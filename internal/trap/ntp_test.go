package trap

import (
	"context"
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

func TestNTPTrap(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := conn.LocalAddr().String()
	conn.Close()

	cfg := &config.Config{
		Addrs:          map[string]string{"ntp": addr},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := metrics.New(prometheus.NewRegistry())
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)
	alerter := alert.NoopAlerter{}

	tr := NewNTP(cfg, logger, m, limiter, alerter)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = tr.Start(ctx) }()
	time.Sleep(50 * time.Millisecond)

	// Build NTP client request
	req := make([]byte, 48)
	req[0] = 0x23 // LI=0, version=4, mode=3
	req[40] = 0x01
	req[41] = 0x02
	req[42] = 0x03
	req[43] = 0x04
	req[44] = 0x05
	req[45] = 0x06
	req[46] = 0x07
	req[47] = 0x08

	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	_, err = c.Write(req)
	if err != nil {
		t.Fatal(err)
	}

	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, 512)
	n, err := c.Read(resp)
	if err != nil {
		t.Fatal(err)
	}
	resp = resp[:n]

	if n != 48 {
		t.Fatalf("response length = %d, want 48", n)
	}

	if resp[0] != 0xE4 {
		t.Errorf("byte 0 = 0x%02x, want 0xE4", resp[0])
	}

	if resp[1] != 0 {
		t.Errorf("stratum = %d, want 0", resp[1])
	}

	if string(resp[12:16]) != "DENY" {
		t.Errorf("reference ID = %q, want \"DENY\"", string(resp[12:16]))
	}

	for i := 0; i < 8; i++ {
		if resp[24+i] != req[40+i] {
			t.Errorf("origin timestamp byte %d = 0x%02x, want 0x%02x", i, resp[24+i], req[40+i])
			break
		}
	}

	// Test mode 7 (monlist) gets no response
	monlist := make([]byte, 48)
	monlist[0] = 0x27 // LI=0, version=4, mode=7

	_, err = c.Write(monlist)
	if err != nil {
		t.Fatal(err)
	}

	_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, err = c.Read(resp)
	if err == nil {
		t.Error("expected no response for mode 7 (monlist), but got one")
	}

	cancel()
	_ = tr.Stop(context.Background())
}
