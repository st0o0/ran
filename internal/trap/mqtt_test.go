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

func testMQTTConfig(addr string) *config.Config {
	return &config.Config{
		Addrs:          map[string]string{"mqtt": addr},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}
}

func buildMQTTConnectPacket(protoName string, protoLevel byte, clientID, username, password string) []byte {
	var payload []byte

	// Protocol name
	payload = binary.BigEndian.AppendUint16(payload, uint16(len(protoName)))
	payload = append(payload, []byte(protoName)...)

	// Protocol level
	payload = append(payload, protoLevel)

	// Connect flags
	var flags byte
	flags |= 0x02 // clean session
	if username != "" {
		flags |= 0x80
	}
	if password != "" {
		flags |= 0x40
	}
	payload = append(payload, flags)

	// Keep alive
	payload = binary.BigEndian.AppendUint16(payload, 60)

	// MQTT 5 properties (empty)
	if protoLevel == 5 {
		payload = append(payload, 0x00)
	}

	// Client ID
	payload = binary.BigEndian.AppendUint16(payload, uint16(len(clientID)))
	payload = append(payload, []byte(clientID)...)

	// Username
	if username != "" {
		payload = binary.BigEndian.AppendUint16(payload, uint16(len(username)))
		payload = append(payload, []byte(username)...)
	}

	// Password
	if password != "" {
		payload = binary.BigEndian.AppendUint16(payload, uint16(len(password)))
		payload = append(payload, []byte(password)...)
	}

	// Fixed header: CONNECT (0x10) + remaining length
	var pkt []byte
	pkt = append(pkt, 0x10)
	pkt = append(pkt, encodeMQTTVarInt(len(payload))...)
	pkt = append(pkt, payload...)
	return pkt
}

func encodeMQTTVarInt(n int) []byte {
	var buf []byte
	for {
		b := byte(n & 0x7F)
		n >>= 7
		if n > 0 {
			b |= 0x80
		}
		buf = append(buf, b)
		if n == 0 {
			break
		}
	}
	return buf
}

func TestMQTTTrapConnect31(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := testMQTTConfig(addr)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewMQTT(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = trap.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	pkt := buildMQTTConnectPacket("MQTT", 4, "test-client", "admin", "secret")
	if _, err := conn.Write(pkt); err != nil {
		t.Fatal(err)
	}

	resp := make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}

	if resp[0] != 0x20 {
		t.Errorf("packet type = 0x%02x, want 0x20", resp[0])
	}
	if resp[1] != 2 {
		t.Errorf("remaining length = %d, want 2", resp[1])
	}
	if resp[2] != 0x00 {
		t.Errorf("session present = 0x%02x, want 0x00", resp[2])
	}
	if resp[3] != 0x04 {
		t.Errorf("return code = 0x%02x, want 0x04", resp[3])
	}

	cancel()
	_ = trap.Stop(context.Background())
}

func TestMQTTTrapConnectV5(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := testMQTTConfig(addr)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewMQTT(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = trap.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	pkt := buildMQTTConnectPacket("MQTT", 5, "v5-client", "user5", "pass5")
	if _, err := conn.Write(pkt); err != nil {
		t.Fatal(err)
	}

	resp := make([]byte, 5)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}

	if resp[0] != 0x20 {
		t.Errorf("packet type = 0x%02x, want 0x20", resp[0])
	}
	if resp[1] != 3 {
		t.Errorf("remaining length = %d, want 3", resp[1])
	}
	if resp[3] != 0x86 {
		t.Errorf("reason code = 0x%02x, want 0x86", resp[3])
	}

	cancel()
	_ = trap.Stop(context.Background())
}

func TestMQTTTrapNonConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := testMQTTConfig(addr)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewMQTT(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = trap.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	// PUBLISH packet (type 3)
	_, _ = conn.Write([]byte{0x30, 0x05, 0x00, 0x01, 'a', 'h', 'i'})

	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Error("expected connection to be closed after non-CONNECT packet")
	}

	cancel()
	_ = trap.Stop(context.Background())
}

func TestMQTTTrapMQIsdpProtocol(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := testMQTTConfig(addr)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewMQTT(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = trap.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	pkt := buildMQTTConnectPacket("MQIsdp", 3, "old-client", "legacyuser", "legacypass")
	if _, err := conn.Write(pkt); err != nil {
		t.Fatal(err)
	}

	resp := make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}

	if resp[0] != 0x20 {
		t.Errorf("packet type = 0x%02x, want 0x20", resp[0])
	}
	if resp[3] != 0x04 {
		t.Errorf("return code = 0x%02x, want 0x04", resp[3])
	}

	cancel()
	_ = trap.Stop(context.Background())
}

func TestParseMQTTConnect(t *testing.T) {
	var payload []byte
	payload = binary.BigEndian.AppendUint16(payload, 4)
	payload = append(payload, "MQTT"...)
	payload = append(payload, 4)    // protocol level
	payload = append(payload, 0xC2) // username + password + clean session
	payload = binary.BigEndian.AppendUint16(payload, 60)

	// Client ID
	payload = binary.BigEndian.AppendUint16(payload, 7)
	payload = append(payload, "mydevice"[:7]...)

	// Username
	payload = binary.BigEndian.AppendUint16(payload, 5)
	payload = append(payload, "admin"...)

	// Password
	payload = binary.BigEndian.AppendUint16(payload, 6)
	payload = append(payload, "secret"...)

	clientID, username, password, level, err := parseMQTTConnect(payload)
	if err != nil {
		t.Fatal(err)
	}
	if clientID != "mydevic" {
		t.Errorf("clientID = %q, want %q", clientID, "mydevic")
	}
	if username != "admin" {
		t.Errorf("username = %q, want %q", username, "admin")
	}
	if password != "secret" {
		t.Errorf("password = %q, want %q", password, "secret")
	}
	if level != 4 {
		t.Errorf("protocol level = %d, want 4", level)
	}
}

func TestBuildMQTTConnack(t *testing.T) {
	connack3 := buildMQTTConnack(4)
	if len(connack3) != 4 {
		t.Fatalf("MQTT 3.x connack length = %d, want 4", len(connack3))
	}
	if connack3[3] != 0x04 {
		t.Errorf("return code = 0x%02x, want 0x04", connack3[3])
	}

	connack5 := buildMQTTConnack(5)
	if len(connack5) != 5 {
		t.Fatalf("MQTT 5 connack length = %d, want 5", len(connack5))
	}
	if connack5[3] != 0x86 {
		t.Errorf("reason code = 0x%02x, want 0x86", connack5[3])
	}
}
