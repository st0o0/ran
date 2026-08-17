package trap

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

func TestParseAddrValid(t *testing.T) {
	host, port := ParseAddr("192.168.1.1:8080")
	if host != "192.168.1.1" {
		t.Errorf("host = %q, want 192.168.1.1", host)
	}
	if port != 8080 {
		t.Errorf("port = %d, want 8080", port)
	}
}

func TestParseAddrPortOnly(t *testing.T) {
	host, port := ParseAddr(":9090")
	if host != "" {
		t.Errorf("host = %q, want empty", host)
	}
	if port != 9090 {
		t.Errorf("port = %d, want 9090", port)
	}
}

func TestParseAddrInvalid(t *testing.T) {
	host, port := ParseAddr("nocolon")
	if host != "nocolon" {
		t.Errorf("host = %q, want nocolon", host)
	}
	if port != 0 {
		t.Errorf("port = %d, want 0", port)
	}
}

func TestParseAddrIPv6(t *testing.T) {
	host, port := ParseAddr("[::1]:22")
	if host != "::1" {
		t.Errorf("host = %q, want ::1", host)
	}
	if port != 22 {
		t.Errorf("port = %d, want 22", port)
	}
}

func TestNewSession(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sess := NewSession("ssh", "10.0.0.1", 4321, 22, logger)
	if sess.Protocol != "ssh" {
		t.Errorf("Protocol = %q, want ssh", sess.Protocol)
	}
	if sess.SourceIP != "10.0.0.1" {
		t.Errorf("SourceIP = %q, want 10.0.0.1", sess.SourceIP)
	}
	if sess.Port != 4321 {
		t.Errorf("Port = %d, want 4321", sess.Port)
	}
	if sess.DestPort != 22 {
		t.Errorf("DestPort = %d, want 22", sess.DestPort)
	}
	if sess.ID == "" {
		t.Error("ID should not be empty")
	}
	if sess.Start.IsZero() {
		t.Error("Start should not be zero")
	}
	if sess.Logger == nil {
		t.Error("Logger should not be nil")
	}
}

func TestDeadlineFromContextBackground(t *testing.T) {
	ctx := context.Background()
	timeout := 5 * time.Second
	dl := deadlineFromContext(ctx, timeout)
	diff := time.Until(dl)
	if diff < 4*time.Second || diff > 6*time.Second {
		t.Errorf("deadline ~%v from now, want ~5s", diff.Round(time.Second))
	}
}

func TestDeadlineFromContextEarlier(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	dl := deadlineFromContext(ctx, 10*time.Second)
	diff := time.Until(dl)
	if diff > 3*time.Second {
		t.Errorf("deadline ~%v from now, should use context deadline (~2s)", diff.Round(time.Second))
	}
}

func TestMultiListenerSingle(t *testing.T) {
	ctx := context.Background()
	ml, err := ListenMultiTCP(ctx, []string{":0"}, false)
	if err != nil {
		t.Fatalf("ListenMultiTCP: %v", err)
	}
	defer ml.Close()

	addr := ml.Addr().String()
	go func() {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			return
		}
		conn.Close()
	}()

	conn, err := ml.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	conn.Close()
}

func TestMultiListenerMultiple(t *testing.T) {
	ctx := context.Background()
	ml, err := ListenMultiTCP(ctx, []string{":0", ":0"}, false)
	if err != nil {
		t.Fatalf("ListenMultiTCP: %v", err)
	}
	defer ml.Close()

	if len(ml.listeners) != 2 {
		t.Fatalf("expected 2 listeners, got %d", len(ml.listeners))
	}

	addr2 := ml.listeners[1].Addr().String()
	go func() {
		conn, err := net.Dial("tcp", addr2)
		if err != nil {
			return
		}
		conn.Close()
	}()

	conn, err := ml.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}

	_, port := ParseAddr(conn.LocalAddr().String())
	_, expectedPort := ParseAddr(addr2)
	if port != expectedPort {
		t.Errorf("conn.LocalAddr port = %d, want %d", port, expectedPort)
	}
	conn.Close()
}

func TestMultiListenerClose(t *testing.T) {
	ctx := context.Background()
	ml, err := ListenMultiTCP(ctx, []string{":0", ":0"}, false)
	if err != nil {
		t.Fatalf("ListenMultiTCP: %v", err)
	}
	ml.Close()

	_, err = ml.Accept()
	if err == nil {
		t.Error("expected error after Close")
	}
}

func TestMultiListenerAddr(t *testing.T) {
	ctx := context.Background()
	ml, err := ListenMultiTCP(ctx, []string{":0", ":0"}, false)
	if err != nil {
		t.Fatalf("ListenMultiTCP: %v", err)
	}
	defer ml.Close()

	if ml.Addr().String() != ml.listeners[0].Addr().String() {
		t.Errorf("Addr() = %v, want first listener addr %v", ml.Addr(), ml.listeners[0].Addr())
	}
}

func TestConnContextWithDestPort(t *testing.T) {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	_, expectedPort := ParseAddr(ln.Addr().String())

	go func() {
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return
		}
		conn.Close()
	}()

	conn, _ := ln.Accept()
	defer conn.Close()

	ctx := ConnContextWithDestPort(context.Background(), conn)
	port := DestPortFromContext(ctx)
	if port != expectedPort {
		t.Errorf("DestPortFromContext = %d, want %d", port, expectedPort)
	}
}

func TestDestPortFromContextMissing(t *testing.T) {
	port := DestPortFromContext(context.Background())
	if port != 0 {
		t.Errorf("DestPortFromContext on empty ctx = %d, want 0", port)
	}
}
