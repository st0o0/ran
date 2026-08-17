package trap

import (
	"context"
	"encoding/binary"
	"encoding/json"
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

func mcBuildHandshake(protocolVersion int32, serverAddr string, serverPort uint16, nextState int32) []byte {
	var payload []byte
	payload = append(payload, 0x00) // packet ID
	payload = append(payload, mcWriteVarint(protocolVersion)...)
	payload = append(payload, mcWriteString(serverAddr)...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, serverPort)
	payload = append(payload, portBuf...)
	payload = append(payload, mcWriteVarint(nextState)...)
	return append(mcWriteVarint(int32(len(payload))), payload...)
}

func startMinecraftTrap(t *testing.T) (*MinecraftTrap, string, context.CancelFunc) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := &config.Config{
		Addrs:          map[string]string{"minecraft": addr},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := metrics.New(prometheus.NewRegistry())
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)
	alerter := alert.NoopAlerter{}

	tr := NewMinecraft(cfg, logger, m, limiter, alerter)

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = tr.Start(ctx) }()
	time.Sleep(50 * time.Millisecond)

	return tr, addr, cancel
}

func TestMinecraftStatusPing(t *testing.T) {
	tr, addr, cancel := startMinecraftTrap(t)
	defer cancel()
	defer func() { _ = tr.Stop(context.Background()) }()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	handshake := mcBuildHandshake(767, "mc.example.com", 25565, 1)
	_, err = conn.Write(handshake)
	if err != nil {
		t.Fatal(err)
	}

	statusReq := mcWritePacket(0x00, nil)
	_, err = conn.Write(statusReq)
	if err != nil {
		t.Fatal(err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil {
		t.Fatal(err)
	}
	resp = resp[:n]

	pktLen, plSize := mcReadVarint(resp)
	if plSize == 0 || pktLen < 2 {
		t.Fatal("invalid response packet")
	}
	payload := resp[plSize:]
	if payload[0] != 0x00 {
		t.Fatalf("packet ID = 0x%02x, want 0x00", payload[0])
	}
	payload = payload[1:]

	jsonStr, _ := mcReadString(payload)
	if jsonStr == "" {
		t.Fatal("empty JSON response")
	}

	var status map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &status); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	version, ok := status["version"].(map[string]interface{})
	if !ok {
		t.Fatal("missing version in status")
	}
	if version["name"] != "1.21.4" {
		t.Errorf("version name = %v, want 1.21.4", version["name"])
	}

	players, ok := status["players"].(map[string]interface{})
	if !ok {
		t.Fatal("missing players in status")
	}
	if players["max"] != float64(20) {
		t.Errorf("max players = %v, want 20", players["max"])
	}
}

func TestMinecraftLoginDisconnect(t *testing.T) {
	tr, addr, cancel := startMinecraftTrap(t)
	defer cancel()
	defer func() { _ = tr.Stop(context.Background()) }()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	handshake := mcBuildHandshake(767, "mc.example.com", 25565, 2)
	_, err = conn.Write(handshake)
	if err != nil {
		t.Fatal(err)
	}

	loginPayload := mcWriteString("Steve")
	loginPkt := mcWritePacket(0x00, loginPayload)
	_, err = conn.Write(loginPkt)
	if err != nil {
		t.Fatal(err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil {
		t.Fatal(err)
	}
	resp = resp[:n]

	pktLen, plSize := mcReadVarint(resp)
	if plSize == 0 || pktLen < 2 {
		t.Fatal("invalid disconnect packet")
	}
	payload := resp[plSize:]
	if payload[0] != 0x00 {
		t.Fatalf("disconnect packet ID = 0x%02x, want 0x00", payload[0])
	}
	payload = payload[1:]

	reason, _ := mcReadString(payload)
	if reason == "" {
		t.Fatal("empty disconnect reason")
	}

	var msg map[string]interface{}
	if err := json.Unmarshal([]byte(reason), &msg); err != nil {
		t.Fatalf("invalid disconnect JSON: %v", err)
	}
	if msg["text"] != "Server is under maintenance" {
		t.Errorf("disconnect reason = %v, want 'Server is under maintenance'", msg["text"])
	}
}

func TestMinecraftMalformedHandshake(t *testing.T) {
	tr, addr, cancel := startMinecraftTrap(t)
	defer cancel()
	defer func() { _ = tr.Stop(context.Background()) }()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}

	_, _ = conn.Write([]byte{0x01})
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 64)
	_, err = conn.Read(buf)
	if err == nil {
		t.Error("expected no response for malformed handshake")
	}
	conn.Close()
}
