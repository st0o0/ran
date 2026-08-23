package trap

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

func testSMBConfig(addr string) *config.Config {
	return &config.Config{
		Addrs:          map[string]string{"smb": addr},
		PerProto:       make(map[string]config.ProtoConfig),
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
		MaxAuthRetries: 3,
	}
}

func buildSMB2NegotiateRequest() []byte {
	header := make([]byte, 64)
	header[0] = 0xFE
	copy(header[1:4], []byte("SMB"))
	binary.LittleEndian.PutUint16(header[4:6], 64)   // StructureSize
	binary.LittleEndian.PutUint16(header[12:14], 0x0000) // Command: Negotiate

	body := make([]byte, 36)
	binary.LittleEndian.PutUint16(body[0:2], 36) // StructureSize
	binary.LittleEndian.PutUint16(body[2:4], 1)  // DialectCount
	binary.LittleEndian.PutUint16(body[4:6], 0x0001) // SecurityMode
	binary.LittleEndian.PutUint16(body[0:], 0x0210) // actually put dialect at end

	// Simplified: just need a valid negotiate message
	negotiate := append(header, body...)
	return negotiate
}

func utf16LEEncode(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	b := make([]byte, len(u16)*2)
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(b[i*2:], v)
	}
	return b
}

func buildSMB2SessionSetupWithNTLMSSP(domain, username, workstation string) []byte {
	// Build NTLMSSP_AUTH message (type 3)
	sig := []byte("NTLMSSP\x00")
	msgType := make([]byte, 4)
	binary.LittleEndian.PutUint32(msgType, 3)

	domainBytes := utf16LEEncode(domain)
	userBytes := utf16LEEncode(username)
	wsBytes := utf16LEEncode(workstation)

	// Fields layout: LmChallengeResponse, NtChallengeResponse, DomainName, UserName, Workstation, EncryptedRandomSessionKey
	// Each field: 2 bytes len, 2 bytes maxlen, 4 bytes offset
	// Header: 8 (sig) + 4 (type) + 6*8 (fields) = 60 bytes
	headerSize := 60
	dataStart := headerSize

	domainOff := dataStart
	userOff := domainOff + len(domainBytes)
	wsOff := userOff + len(userBytes)

	ntlmssp := make([]byte, headerSize)
	copy(ntlmssp, sig)
	copy(ntlmssp[8:], msgType)

	// LmChallengeResponse (offset 12) - empty
	binary.LittleEndian.PutUint16(ntlmssp[12:], 0)
	binary.LittleEndian.PutUint16(ntlmssp[14:], 0)
	binary.LittleEndian.PutUint32(ntlmssp[16:], uint32(dataStart))

	// NtChallengeResponse (offset 20) - empty
	binary.LittleEndian.PutUint16(ntlmssp[20:], 0)
	binary.LittleEndian.PutUint16(ntlmssp[22:], 0)
	binary.LittleEndian.PutUint32(ntlmssp[24:], uint32(dataStart))

	// DomainName (offset 28)
	binary.LittleEndian.PutUint16(ntlmssp[28:], uint16(len(domainBytes)))
	binary.LittleEndian.PutUint16(ntlmssp[30:], uint16(len(domainBytes)))
	binary.LittleEndian.PutUint32(ntlmssp[32:], uint32(domainOff))

	// UserName (offset 36)
	binary.LittleEndian.PutUint16(ntlmssp[36:], uint16(len(userBytes)))
	binary.LittleEndian.PutUint16(ntlmssp[38:], uint16(len(userBytes)))
	binary.LittleEndian.PutUint32(ntlmssp[40:], uint32(userOff))

	// Workstation (offset 44)
	binary.LittleEndian.PutUint16(ntlmssp[44:], uint16(len(wsBytes)))
	binary.LittleEndian.PutUint16(ntlmssp[46:], uint16(len(wsBytes)))
	binary.LittleEndian.PutUint32(ntlmssp[48:], uint32(wsOff))

	// EncryptedRandomSessionKey (offset 52) - empty
	binary.LittleEndian.PutUint16(ntlmssp[52:], 0)
	binary.LittleEndian.PutUint16(ntlmssp[54:], 0)
	binary.LittleEndian.PutUint32(ntlmssp[56:], uint32(wsOff+len(wsBytes)))

	ntlmssp = append(ntlmssp, domainBytes...)
	ntlmssp = append(ntlmssp, userBytes...)
	ntlmssp = append(ntlmssp, wsBytes...)

	// SMB2 header
	header := make([]byte, 64)
	header[0] = 0xFE
	copy(header[1:4], []byte("SMB"))
	binary.LittleEndian.PutUint16(header[4:6], 64) // StructureSize
	binary.LittleEndian.PutUint16(header[12:14], 0x0001) // Command: Session Setup

	// Session Setup request body
	body := make([]byte, 24)
	binary.LittleEndian.PutUint16(body[0:2], 25) // StructureSize
	// SecurityBufferOffset = header(64) + body(24) = 88
	binary.LittleEndian.PutUint16(body[12:14], 88) // SecurityBufferOffset
	binary.LittleEndian.PutUint16(body[14:16], uint16(len(ntlmssp))) // SecurityBufferLength

	msg := append(header, body...)
	msg = append(msg, ntlmssp...)
	return msg
}

func TestSMBTrapNegotiate(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := testSMBConfig(addr)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewSMB(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
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

	negReq := buildSMB2NegotiateRequest()
	_ = smbWriteMessage(conn, negReq)

	resp, err := smbReadMessage(conn)
	if err != nil {
		t.Fatal(err)
	}

	if len(resp) < 4 {
		t.Fatal("response too short")
	}
	if resp[0] != 0xFE || resp[1] != 'S' || resp[2] != 'M' || resp[3] != 'B' {
		t.Fatalf("expected SMB2 magic, got %x", resp[:4])
	}

	cancel()
	_ = trap.Stop(context.Background())
}

func TestSMBTrapSessionSetup(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := testSMBConfig(addr)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewSMB(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
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

	// Send negotiate first
	negReq := buildSMB2NegotiateRequest()
	if err := smbWriteMessage(conn, negReq); err != nil {
		t.Fatal(err)
	}
	_, err = smbReadMessage(conn)
	if err != nil {
		t.Fatal(err)
	}

	// Send session setup with NTLMSSP auth
	setupReq := buildSMB2SessionSetupWithNTLMSSP("WORKGROUP", "administrator", "DESKTOP-TEST")
	if err := smbWriteMessage(conn, setupReq); err != nil {
		t.Fatal(err)
	}

	resp, err := smbReadMessage(conn)
	if err != nil {
		t.Fatal(err)
	}

	if len(resp) < 12 {
		t.Fatal("response too short")
	}

	status := binary.LittleEndian.Uint32(resp[8:12])
	if status != 0xC000006D {
		t.Fatalf("status = 0x%08X, want 0xC000006D (STATUS_LOGON_FAILURE)", status)
	}

	cancel()
	_ = trap.Stop(context.Background())
}

func TestSMB1Negotiate(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := testSMBConfig(addr)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewSMB(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
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

	// SMB1 negotiate
	header := make([]byte, 32)
	header[0] = 0xFF
	copy(header[1:4], []byte("SMB"))
	header[4] = 0x72 // Negotiate command

	dialects := []byte{0x02}
	dialects = append(dialects, []byte("NT LM 0.12")...)
	dialects = append(dialects, 0x00)

	body := make([]byte, 3)
	body[0] = 0 // word count
	binary.LittleEndian.PutUint16(body[1:3], uint16(len(dialects)))
	body = append(body, dialects...)

	msg := append(header, body...)
	if err := smbWriteMessage(conn, msg); err != nil {
		t.Fatal(err)
	}

	resp, err := smbReadMessage(conn)
	if err != nil {
		t.Fatal(err)
	}

	if len(resp) < 4 || resp[0] != 0xFF || resp[1] != 'S' || resp[2] != 'M' || resp[3] != 'B' {
		t.Fatalf("expected SMB1 magic in response")
	}

	cancel()
	_ = trap.Stop(context.Background())
}

func TestSMBProbeOutcome(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := testSMBConfig(addr)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	smbTrap := NewSMB(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = smbTrap.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// Send non-SMB data via NetBIOS framing
	garbage := []byte("NOT-SMB-DATA-HERE")
	var hdr [4]byte
	hdr[1] = byte(len(garbage) >> 16)
	hdr[2] = byte(len(garbage) >> 8)
	hdr[3] = byte(len(garbage))
	conn.Write(hdr[:])
	conn.Write(garbage)
	conn.Close()

	time.Sleep(200 * time.Millisecond)

	families, _ := reg.Gather()
	found := false
	for _, f := range families {
		if f.GetName() == "ran_connections_total" {
			for _, met := range f.GetMetric() {
				var proto, outcome string
				for _, l := range met.GetLabel() {
					switch l.GetName() {
					case "protocol":
						proto = l.GetValue()
					case "outcome":
						outcome = l.GetValue()
					}
				}
				if proto == "smb" && outcome == "probe" && met.GetCounter().GetValue() >= 1 {
					found = true
				}
			}
		}
	}
	if !found {
		t.Error("expected ran_connections_total{protocol=smb,outcome=probe} >= 1")
	}

	cancel()
	_ = smbTrap.Stop(context.Background())
}
