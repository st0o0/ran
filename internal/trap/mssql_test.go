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

func mssqlTestConfig(t *testing.T) *config.Config {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	return &config.Config{
		Addrs:          map[string]string{"mssql": addr},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}
}

func TestTDSPasswordDecode(t *testing.T) {
	// Encode "password" as TDS password
	plain := stringToUTF16LE("password")
	encoded := make([]byte, len(plain))
	for i, b := range plain {
		b = (b << 4) | (b >> 4)
		b ^= 0xA5
		encoded[i] = b
	}
	got := decodeTDSPassword(encoded)
	if got != "password" {
		t.Errorf("decoded = %q, want password", got)
	}
}

func TestTDSPreloginResponse(t *testing.T) {
	pkt := buildTDSPreloginResponse()
	if len(pkt) < 8 {
		t.Fatal("prelogin response too short")
	}
	if pkt[0] != 0x12 {
		t.Errorf("type = 0x%02X, want 0x12", pkt[0])
	}
	if pkt[1] != 0x01 {
		t.Errorf("status = 0x%02X, want 0x01", pkt[1])
	}
	pktLen := binary.BigEndian.Uint16(pkt[2:4])
	if int(pktLen) != len(pkt) {
		t.Errorf("length = %d, packet size = %d", pktLen, len(pkt))
	}
}

func TestTDSErrorResponse(t *testing.T) {
	pkt := buildTDSErrorResponse()
	if len(pkt) < 8 {
		t.Fatal("error response too short")
	}
	if pkt[0] != 0x04 {
		t.Errorf("type = 0x%02X, want 0x04", pkt[0])
	}
	if pkt[8] != 0xAA {
		t.Errorf("token = 0x%02X, want 0xAA", pkt[8])
	}
}

func TestParseTDSLogin7(t *testing.T) {
	user := "sa"
	pass := "P@ssw0rd"

	userUTF16 := stringToUTF16LE(user)
	passUTF16 := stringToUTF16LE(pass)

	// Encode password for TDS
	encodedPass := make([]byte, len(passUTF16))
	for i, b := range passUTF16 {
		b = (b << 4) | (b >> 4)
		b ^= 0xA5
		encodedPass[i] = b
	}

	// Build Login7 body: 64 bytes fixed + variable data
	body := make([]byte, 64)
	// Total length at offset 0
	totalLen := 64 + len(userUTF16) + len(encodedPass)
	binary.LittleEndian.PutUint32(body[0:4], uint32(totalLen))

	// Username offset/length at bytes 56-59
	binary.LittleEndian.PutUint16(body[56:58], 64)                        // offset
	binary.LittleEndian.PutUint16(body[58:60], uint16(len(userUTF16)/2))  // length in chars

	// Password offset/length at bytes 60-63
	binary.LittleEndian.PutUint16(body[60:62], uint16(64+len(userUTF16))) // offset
	binary.LittleEndian.PutUint16(body[62:64], uint16(len(encodedPass)/2)) // length in chars

	body = append(body, userUTF16...)
	body = append(body, encodedPass...)

	gotUser, gotPass := parseTDSLogin7(body)
	if gotUser != user {
		t.Errorf("username = %q, want %q", gotUser, user)
	}
	if gotPass != pass {
		t.Errorf("password = %q, want %q", gotPass, pass)
	}
}

func TestMSSQLTrapConnection(t *testing.T) {
	cfg := mssqlTestConfig(t)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewMSSQL(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go trap.Start(ctx)
	time.Sleep(100 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", cfg.Addrs["mssql"], 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send TDS prelogin
	preloginPayload := []byte{
		0x00, 0x00, 0x06, 0x00, 0x06, // VERSION option
		0xFF,                         // TERMINATOR
		0x0F, 0x00, 0x07, 0xD0, 0x00, 0x00, // VERSION data
	}
	conn.Write(buildTDSPacket(0x12, 0x01, preloginPayload))

	// Read prelogin response
	header := make([]byte, 8)
	if _, err := io.ReadFull(conn, header); err != nil {
		t.Fatal(err)
	}
	if header[0] != 0x12 {
		t.Errorf("response type = 0x%02X, want 0x12", header[0])
	}
	respLen := int(binary.BigEndian.Uint16(header[2:4])) - 8
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}

	// Send Login7
	user := "sa"
	pass := "Secret123"
	userUTF16 := stringToUTF16LE(user)
	passUTF16 := stringToUTF16LE(pass)
	encodedPass := make([]byte, len(passUTF16))
	for i, b := range passUTF16 {
		b = (b << 4) | (b >> 4)
		b ^= 0xA5
		encodedPass[i] = b
	}

	body := make([]byte, 64)
	totalLen := 64 + len(userUTF16) + len(encodedPass)
	binary.LittleEndian.PutUint32(body[0:4], uint32(totalLen))
	binary.LittleEndian.PutUint16(body[56:58], 64)
	binary.LittleEndian.PutUint16(body[58:60], uint16(len(userUTF16)/2))
	binary.LittleEndian.PutUint16(body[60:62], uint16(64+len(userUTF16)))
	binary.LittleEndian.PutUint16(body[62:64], uint16(len(encodedPass)/2))
	body = append(body, userUTF16...)
	body = append(body, encodedPass...)
	conn.Write(buildTDSPacket(0x10, 0x01, body))

	// Read TDS error response
	if _, err := io.ReadFull(conn, header); err != nil {
		t.Fatal(err)
	}
	if header[0] != 0x04 {
		t.Errorf("error type = 0x%02X, want 0x04", header[0])
	}
	errLen := int(binary.BigEndian.Uint16(header[2:4])) - 8
	errPayload := make([]byte, errLen)
	if _, err := io.ReadFull(conn, errPayload); err != nil {
		t.Fatal(err)
	}
	if errPayload[0] != 0xAA {
		t.Errorf("error token = 0x%02X, want 0xAA", errPayload[0])
	}

	cancel()
	trap.Stop(context.Background())
}
