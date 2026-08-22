package trap

import (
	"context"
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

func TestSIPTrap(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := conn.LocalAddr().String()
	conn.Close()

	cfg := &config.Config{
		Addrs:          map[string]string{"sip": addr},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := metrics.New(prometheus.NewRegistry(), "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)
	alerter := alert.NoopAlerter{}

	trap := NewSIP(cfg, logger, m, limiter, alerter)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = trap.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	request := "REGISTER sip:example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK776\r\n" +
		"From: <sip:alice@example.com>;tag=123\r\n" +
		"To: <sip:alice@example.com>\r\n" +
		"Call-ID: abc@10.0.0.1\r\n" +
		"Contact: <sip:alice@10.0.0.1:5060>\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n"

	udpConn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()

	if _, err := udpConn.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}

	_ = udpConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, err := udpConn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}

	response := string(buf[:n])

	if !strings.Contains(response, "SIP/2.0 401 Unauthorized") {
		t.Errorf("response missing status line, got: %s", response)
	}
	if !strings.Contains(response, "WWW-Authenticate") {
		t.Errorf("response missing WWW-Authenticate header, got: %s", response)
	}
	if !strings.Contains(response, "Via:") {
		t.Errorf("response missing Via header, got: %s", response)
	}
	if !strings.Contains(response, "abc@10.0.0.1") {
		t.Errorf("response missing Call-ID, got: %s", response)
	}

	cancel()
	_ = trap.Stop(context.Background())
}
