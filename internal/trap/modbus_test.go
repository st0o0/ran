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

func testModbusConfig(addr string) *config.Config {
	return &config.Config{
		Addrs:          map[string]string{"modbus": addr},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}
}

func buildModbusRequest(transactionID uint16, unitID byte, fc byte, data []byte) []byte {
	pduLen := 1 + len(data)
	pkt := make([]byte, 7+pduLen)
	binary.BigEndian.PutUint16(pkt[0:2], transactionID)
	binary.BigEndian.PutUint16(pkt[2:4], 0) // protocol ID
	binary.BigEndian.PutUint16(pkt[4:6], uint16(pduLen+1))
	pkt[6] = unitID
	pkt[7] = fc
	copy(pkt[8:], data)
	return pkt
}

func TestModbusTrapReadCoils(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := testModbusConfig(addr)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewModbus(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
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

	// FC 1: Read Coils, starting address 0x0000, quantity 10
	data := make([]byte, 4)
	binary.BigEndian.PutUint16(data[0:2], 0x0000)
	binary.BigEndian.PutUint16(data[2:4], 10)
	req := buildModbusRequest(0x0001, 0x01, 0x01, data)
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}

	resp := make([]byte, 9)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}

	respTxID := binary.BigEndian.Uint16(resp[0:2])
	if respTxID != 0x0001 {
		t.Errorf("transaction ID = 0x%04x, want 0x0001", respTxID)
	}
	respProto := binary.BigEndian.Uint16(resp[2:4])
	if respProto != 0 {
		t.Errorf("protocol ID = %d, want 0", respProto)
	}
	respLen := binary.BigEndian.Uint16(resp[4:6])
	if respLen != 3 {
		t.Errorf("length = %d, want 3", respLen)
	}
	if resp[6] != 0x01 {
		t.Errorf("unit ID = 0x%02x, want 0x01", resp[6])
	}
	if resp[7] != 0x81 {
		t.Errorf("exception FC = 0x%02x, want 0x81", resp[7])
	}
	if resp[8] != 0x01 {
		t.Errorf("exception code = 0x%02x, want 0x01", resp[8])
	}

	cancel()
	_ = trap.Stop(context.Background())
}

func TestModbusTrapWriteSingleRegister(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := testModbusConfig(addr)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewModbus(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
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

	// FC 6: Write Single Register, address 0x0010, value 0x00FF
	data := make([]byte, 4)
	binary.BigEndian.PutUint16(data[0:2], 0x0010)
	binary.BigEndian.PutUint16(data[2:4], 0x00FF)
	req := buildModbusRequest(0x0042, 0x03, 0x06, data)
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}

	resp := make([]byte, 9)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}

	respTxID := binary.BigEndian.Uint16(resp[0:2])
	if respTxID != 0x0042 {
		t.Errorf("transaction ID = 0x%04x, want 0x0042", respTxID)
	}
	if resp[7] != 0x86 {
		t.Errorf("exception FC = 0x%02x, want 0x86", resp[7])
	}
	if resp[8] != 0x01 {
		t.Errorf("exception code = 0x%02x, want 0x01", resp[8])
	}

	cancel()
	_ = trap.Stop(context.Background())
}

func TestModbusTrapInvalidProtocolID(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := testModbusConfig(addr)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewModbus(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
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

	// Invalid protocol ID (should be 0)
	pkt := make([]byte, 12)
	binary.BigEndian.PutUint16(pkt[0:2], 1)    // transaction ID
	binary.BigEndian.PutUint16(pkt[2:4], 0x01)  // bad protocol ID
	binary.BigEndian.PutUint16(pkt[4:6], 5)     // length
	pkt[6] = 1                                   // unit ID
	pkt[7] = 1                                   // FC
	binary.BigEndian.PutUint16(pkt[8:10], 0)     // address
	binary.BigEndian.PutUint16(pkt[10:12], 10)   // quantity
	_, _ = conn.Write(pkt)

	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Error("expected connection to be closed after invalid protocol ID")
	}

	cancel()
	_ = trap.Stop(context.Background())
}

func TestModbusTrapWriteMultipleRegisters(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := testModbusConfig(addr)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewModbus(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
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

	// FC 16: Write Multiple Registers, address 0x0000, quantity 2, byte count 4, values
	data := make([]byte, 9)
	binary.BigEndian.PutUint16(data[0:2], 0x0000)
	binary.BigEndian.PutUint16(data[2:4], 2)
	data[4] = 4 // byte count
	binary.BigEndian.PutUint16(data[5:7], 0x000A)
	binary.BigEndian.PutUint16(data[7:9], 0x0102)
	req := buildModbusRequest(0x0003, 0x01, 0x10, data)
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}

	resp := make([]byte, 9)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}

	if resp[7] != 0x90 {
		t.Errorf("exception FC = 0x%02x, want 0x90", resp[7])
	}

	cancel()
	_ = trap.Stop(context.Background())
}

func TestBuildModbusException(t *testing.T) {
	resp := buildModbusException(0x1234, 0x05, 0x03, 0x01)
	if len(resp) != 9 {
		t.Fatalf("response length = %d, want 9", len(resp))
	}

	txID := binary.BigEndian.Uint16(resp[0:2])
	if txID != 0x1234 {
		t.Errorf("transaction ID = 0x%04x, want 0x1234", txID)
	}
	proto := binary.BigEndian.Uint16(resp[2:4])
	if proto != 0 {
		t.Errorf("protocol ID = %d, want 0", proto)
	}
	length := binary.BigEndian.Uint16(resp[4:6])
	if length != 3 {
		t.Errorf("length = %d, want 3", length)
	}
	if resp[6] != 0x05 {
		t.Errorf("unit ID = 0x%02x, want 0x05", resp[6])
	}
	if resp[7] != 0x83 {
		t.Errorf("exception FC = 0x%02x, want 0x83", resp[7])
	}
	if resp[8] != 0x01 {
		t.Errorf("exception code = 0x%02x, want 0x01", resp[8])
	}
}

func TestParseModbusPDU(t *testing.T) {
	// FC 1: Read Coils
	data := make([]byte, 4)
	binary.BigEndian.PutUint16(data[0:2], 100)
	binary.BigEndian.PutUint16(data[2:4], 25)
	attrs := parseModbusPDU(1, data)

	if len(attrs) != 3 {
		t.Fatalf("attrs count = %d, want 3", len(attrs))
	}
	if attrs[0].Value.String() != "1" {
		t.Errorf("function_code = %s, want 1", attrs[0].Value.String())
	}

	// FC 6: Write Single Register
	attrs = parseModbusPDU(6, data)
	if len(attrs) != 3 {
		t.Fatalf("attrs count = %d, want 3", len(attrs))
	}
	if attrs[1].Key != "address" {
		t.Errorf("second attr key = %s, want address", attrs[1].Key)
	}
}
