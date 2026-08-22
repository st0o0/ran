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

func postgresTestConfig(t *testing.T) *config.Config {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	return &config.Config{
		Addrs:          map[string]string{"postgres": addr},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}
}

func TestPgStartupParamsParsing(t *testing.T) {
	// version 3.0 = int32
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, 196608) // 3<<16
	data = append(data, "user\x00admin\x00database\x00testdb\x00\x00"...)

	user := parsePgStartupParams(data)
	if user != "admin" {
		t.Errorf("username = %q, want admin", user)
	}
}

func TestPgErrorResponse(t *testing.T) {
	r, w := io.Pipe()
	go func() {
		writePgErrorResponse(w, "password authentication failed for user \"test\"")
		w.Close()
	}()

	var tag [1]byte
	if _, err := io.ReadFull(r, tag[:]); err != nil {
		t.Fatal(err)
	}
	if tag[0] != 'E' {
		t.Errorf("tag = %c, want E", tag[0])
	}

	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		t.Fatal(err)
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	body := make([]byte, length-4)
	if _, err := io.ReadFull(r, body); err != nil {
		t.Fatal(err)
	}
	if body[0] != 'S' {
		t.Errorf("first field = %c, want S", body[0])
	}
}

func TestPostgresTrapConnection(t *testing.T) {
	cfg := postgresTestConfig(t)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewPostgres(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = trap.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", cfg.Addrs["postgres"], 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send SSLRequest
	var sslReq [8]byte
	binary.BigEndian.PutUint32(sslReq[0:4], 8)
	binary.BigEndian.PutUint32(sslReq[4:8], 80877103)
	_, _ = conn.Write(sslReq[:])

	// Read SSL rejection
	var sslResp [1]byte
	if _, err := io.ReadFull(conn, sslResp[:]); err != nil {
		t.Fatal(err)
	}
	if sslResp[0] != 'N' {
		t.Errorf("ssl response = %c, want N", sslResp[0])
	}

	// Send StartupMessage
	var startup []byte
	version := make([]byte, 4)
	binary.BigEndian.PutUint32(version, 196608) // 3.0
	startup = append(startup, version...)
	startup = append(startup, "user\x00attacker\x00database\x00postgres\x00\x00"...)
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(4+len(startup)))
	_, _ = conn.Write(append(length, startup...))

	// Read AuthenticationCleartextPassword
	auth := make([]byte, 9)
	if _, err := io.ReadFull(conn, auth); err != nil {
		t.Fatal(err)
	}
	if auth[0] != 'R' {
		t.Errorf("auth tag = %c, want R", auth[0])
	}
	authType := binary.BigEndian.Uint32(auth[5:9])
	if authType != 3 {
		t.Errorf("auth type = %d, want 3 (cleartext)", authType)
	}

	// Send PasswordMessage
	password := "s3cret"
	var pwMsg []byte
	pwMsg = append(pwMsg, 'p')
	pwLen := make([]byte, 4)
	binary.BigEndian.PutUint32(pwLen, uint32(4+len(password)+1))
	pwMsg = append(pwMsg, pwLen...)
	pwMsg = append(pwMsg, password...)
	pwMsg = append(pwMsg, 0)
	_, _ = conn.Write(pwMsg)

	// Read ErrorResponse
	var errTag [1]byte
	if _, err := io.ReadFull(conn, errTag[:]); err != nil {
		t.Fatal(err)
	}
	if errTag[0] != 'E' {
		t.Errorf("error tag = %c, want E", errTag[0])
	}

	cancel()
	_ = trap.Stop(context.Background())
}

func TestPostgresTrapConnectionNoSSL(t *testing.T) {
	cfg := postgresTestConfig(t)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewPostgres(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = trap.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", cfg.Addrs["postgres"], 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send StartupMessage directly (no SSL)
	var startup []byte
	version := make([]byte, 4)
	binary.BigEndian.PutUint32(version, 196608)
	startup = append(startup, version...)
	startup = append(startup, "user\x00root\x00\x00"...)
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(4+len(startup)))
	_, _ = conn.Write(append(length, startup...))

	// Read AuthenticationCleartextPassword
	auth := make([]byte, 9)
	if _, err := io.ReadFull(conn, auth); err != nil {
		t.Fatal(err)
	}
	if auth[0] != 'R' {
		t.Fatalf("auth tag = %c, want R", auth[0])
	}

	// Send password
	var pwMsg []byte
	pwMsg = append(pwMsg, 'p')
	pwLen := make([]byte, 4)
	binary.BigEndian.PutUint32(pwLen, uint32(4+len("pass")+1))
	pwMsg = append(pwMsg, pwLen...)
	pwMsg = append(pwMsg, "pass"...)
	pwMsg = append(pwMsg, 0)
	_, _ = conn.Write(pwMsg)

	// Read ErrorResponse
	var errTag [1]byte
	if _, err := io.ReadFull(conn, errTag[:]); err != nil {
		t.Fatal(err)
	}
	if errTag[0] != 'E' {
		t.Errorf("error tag = %c, want E", errTag[0])
	}

	cancel()
	_ = trap.Stop(context.Background())
}
