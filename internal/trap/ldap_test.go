package trap

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

func testLDAPConfig(addr string) *config.Config {
	return &config.Config{
		Addrs:          map[string]string{"ldap": addr},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}
}

func buildBindRequest(msgID int, dn, password string) []byte {
	msgIDBytes := berInteger(0x02, int64(msgID))

	version := berInteger(0x02, 3)
	name := berOctetString(0x04, []byte(dn))
	auth := []byte{0x80, byte(len(password))}
	auth = append(auth, []byte(password)...)

	bindReq := berSequence(0x60, version, name, auth)
	return berSequence(0x30, msgIDBytes, bindReq)
}

func buildUnbindRequest(msgID int) []byte {
	msgIDBytes := berInteger(0x02, int64(msgID))
	unbind := []byte{0x42, 0x00}
	return berSequence(0x30, msgIDBytes, unbind)
}

func buildSearchRequest(msgID int) []byte {
	msgIDBytes := berInteger(0x02, int64(msgID))

	baseObject := berOctetString(0x04, []byte("dc=example,dc=com"))
	scope := berInteger(0x0a, 2) // wholeSubtree
	deref := berInteger(0x0a, 0)
	sizeLimit := berInteger(0x02, 0)
	timeLimit := berInteger(0x02, 0)
	typesOnly := []byte{0x01, 0x01, 0x00}
	filter := []byte{0x87, 0x0b}
	filter = append(filter, []byte("objectClass")...)
	attrs := berSequence(0x30)

	searchReq := berSequence(0x63, baseObject, scope, deref, sizeLimit, timeLimit, typesOnly, filter, attrs)
	return berSequence(0x30, msgIDBytes, searchReq)
}

func TestLDAPTrapBindRequest(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := testLDAPConfig(addr)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewLDAP(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
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

	req := buildBindRequest(1, "cn=admin,dc=example,dc=com", "secret123")
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}

	tag, respBytes, err := berReadElement(conn)
	if err != nil {
		t.Fatal(err)
	}
	if tag != 0x30 {
		t.Fatalf("response tag = 0x%02x, want 0x30", tag)
	}

	_, rest, err := berReadInteger(respBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) == 0 || rest[0] != 0x61 {
		t.Fatalf("expected BindResponse (0x61), got 0x%02x", rest[0])
	}

	_, bindRespBody, err := berReadTLV(rest)
	if err != nil {
		t.Fatal(err)
	}

	if len(bindRespBody) < 2 || bindRespBody[0] != 0x0a {
		t.Fatalf("expected ENUMERATED tag 0x0a, got 0x%02x", bindRespBody[0])
	}
	length := int(bindRespBody[1])
	if 2+length > len(bindRespBody) {
		t.Fatal("truncated result code")
	}
	var resultCode int64
	for _, b := range bindRespBody[2 : 2+length] {
		resultCode = (resultCode << 8) | int64(b)
	}
	if resultCode != 49 {
		t.Fatalf("resultCode = %d, want 49 (invalidCredentials)", resultCode)
	}

	cancel()
	_ = trap.Stop(context.Background())
}

func TestLDAPTrapSearchRequest(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := testLDAPConfig(addr)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewLDAP(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
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

	req := buildSearchRequest(2)
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}

	tag, respBytes, err := berReadElement(conn)
	if err != nil {
		t.Fatal(err)
	}
	if tag != 0x30 {
		t.Fatalf("response tag = 0x%02x, want 0x30", tag)
	}

	_, rest, err := berReadInteger(respBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) == 0 || rest[0] != 0x65 {
		t.Fatalf("expected SearchResultDone (0x65), got 0x%02x", rest[0])
	}

	cancel()
	_ = trap.Stop(context.Background())
}

func TestLDAPTrapUnbind(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := testLDAPConfig(addr)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewLDAP(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
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

	req := buildUnbindRequest(3)
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("expected connection to close after unbind")
	}

	cancel()
	_ = trap.Stop(context.Background())
}
