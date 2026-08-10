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

func mysqlTestConfig(t *testing.T) *config.Config {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	return &config.Config{
		Traps:          []string{"mysql"},
		Addrs:          map[string]string{"mysql": addr},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}
}

func TestMySQLGreeting(t *testing.T) {
	challenge := make([]byte, 20)
	for i := range challenge {
		challenge[i] = byte(i)
	}
	pkt := buildGreeting(1, challenge)

	// Verify packet structure
	length := int(pkt[0]) | int(pkt[1])<<8 | int(pkt[2])<<16
	if length != len(pkt)-4 {
		t.Errorf("packet length = %d, payload = %d", length, len(pkt)-4)
	}
	if pkt[3] != 0 { // sequence number
		t.Errorf("sequence = %d, want 0", pkt[3])
	}
	if pkt[4] != 10 { // protocol version
		t.Errorf("protocol = %d, want 10", pkt[4])
	}
	// Check server version starts with "5.7.99-ran"
	verEnd := 5
	for verEnd < len(pkt) && pkt[verEnd] != 0 {
		verEnd++
	}
	ver := string(pkt[5:verEnd])
	if ver != "5.7.99-ran" {
		t.Errorf("version = %q, want 5.7.99-ran", ver)
	}
}

func TestMySQLHandshakeResponseParsing(t *testing.T) {
	// Build a minimal handshake response
	var resp []byte

	// Client capabilities (4 bytes)
	resp = binary.LittleEndian.AppendUint32(resp, 0x000FA68D)
	// Max packet size (4 bytes)
	resp = binary.LittleEndian.AppendUint32(resp, 1<<24)
	// Charset (1 byte)
	resp = append(resp, 0x21)
	// Reserved (23 bytes)
	resp = append(resp, make([]byte, 23)...)
	// Username null-terminated
	resp = append(resp, []byte("testuser\x00")...)
	// Auth data length + data (plaintext password)
	resp = append(resp, byte(len("secret123")))
	resp = append(resp, []byte("secret123")...)

	user, pass := parseHandshakeResponse(resp, nil)
	if user != "testuser" {
		t.Errorf("username = %q, want testuser", user)
	}
	if pass != "secret123" {
		t.Errorf("password = %q, want secret123", pass)
	}
}

func TestMySQLErrPacket(t *testing.T) {
	pkt := buildErrPacket(2, 1045, "28000", "Access denied")
	payload := pkt[4:]
	if payload[0] != 0xFF {
		t.Errorf("marker = %d, want 0xFF", payload[0])
	}
	code := binary.LittleEndian.Uint16(payload[1:3])
	if code != 1045 {
		t.Errorf("error code = %d, want 1045", code)
	}
}

func TestMySQLTrapConnection(t *testing.T) {
	cfg := mysqlTestConfig(t)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewMySQL(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = trap.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", cfg.TrapAddr("mysql"), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Read greeting
	header := make([]byte, 4)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(header); err != nil {
		t.Fatal(err)
	}
	length := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	payload := make([]byte, length)
	if _, err := conn.Read(payload); err != nil {
		t.Fatal(err)
	}
	if payload[0] != 10 {
		t.Errorf("protocol = %d, want 10", payload[0])
	}

	// Send handshake response with plaintext password
	var resp []byte
	resp = binary.LittleEndian.AppendUint32(resp, 0x000FA68D)
	resp = binary.LittleEndian.AppendUint32(resp, 1<<24)
	resp = append(resp, 0x21)
	resp = append(resp, make([]byte, 23)...)
	resp = append(resp, []byte("scanner\x00")...)
	resp = append(resp, byte(len("password123")))
	resp = append(resp, []byte("password123")...)

	pkt := wrapMySQLPacket(1, resp)
	_, _ = conn.Write(pkt)

	// Read ERR response
	errHeader := make([]byte, 4)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(errHeader); err != nil {
		t.Fatal(err)
	}
	errLen := int(errHeader[0]) | int(errHeader[1])<<8 | int(errHeader[2])<<16
	errPayload := make([]byte, errLen)
	if _, err := conn.Read(errPayload); err != nil {
		t.Fatal(err)
	}
	if errPayload[0] != 0xFF {
		t.Errorf("expected ERR packet, got %d", errPayload[0])
	}

	cancel()
	_ = trap.Stop(context.Background())
}
