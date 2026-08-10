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

func TestDNSTrap(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	cfg := &config.Config{
		Addrs:          map[string]string{"dns": conn.LocalAddr().String()},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}
	conn.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := metrics.New(prometheus.NewRegistry())
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)
	alerter := alert.NoopAlerter{}

	tr := NewDNS(cfg, logger, m, limiter, alerter)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tr.Start(ctx)
	time.Sleep(50 * time.Millisecond)

	// Build DNS query for "example.com" type A
	query := make([]byte, 0, 512)
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], 0x1234)  // ID
	binary.BigEndian.PutUint16(header[2:4], 0x0100)  // flags: standard query
	binary.BigEndian.PutUint16(header[4:6], 1)        // qdcount
	query = append(query, header...)

	// Question: example.com
	query = append(query, 7)
	query = append(query, "example"...)
	query = append(query, 3)
	query = append(query, "com"...)
	query = append(query, 0) // terminator
	// qtype=1 (A), qclass=1 (IN)
	query = append(query, 0, 1, 0, 1)

	addr := cfg.Addrs["dns"]
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	_, err = c.Write(query)
	if err != nil {
		t.Fatal(err)
	}

	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, 512)
	n, err := c.Read(resp)
	if err != nil {
		t.Fatal(err)
	}
	resp = resp[:n]

	if n < 12 {
		t.Fatalf("response too short: %d bytes", n)
	}

	respID := binary.BigEndian.Uint16(resp[0:2])
	if respID != 0x1234 {
		t.Errorf("transaction ID = 0x%04x, want 0x1234", respID)
	}

	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags != 0x8005 {
		t.Errorf("flags = 0x%04x, want 0x8005", flags)
	}

	qdcount := binary.BigEndian.Uint16(resp[4:6])
	if qdcount != 1 {
		t.Errorf("qdcount = %d, want 1", qdcount)
	}

	// Verify question section is echoed back
	questionSection := query[12:]
	if n < 12+len(questionSection) {
		t.Fatal("response does not contain full question section")
	}
	for i, b := range questionSection {
		if resp[12+i] != b {
			t.Errorf("question byte %d = 0x%02x, want 0x%02x", i, resp[12+i], b)
			break
		}
	}

	cancel()
	tr.Stop(context.Background())
}
