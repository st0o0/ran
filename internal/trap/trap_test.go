package trap

import (
	"context"
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
	sess := NewSession("ssh", "10.0.0.1", 4321)
	if sess.Protocol != "ssh" {
		t.Errorf("Protocol = %q, want ssh", sess.Protocol)
	}
	if sess.SourceIP != "10.0.0.1" {
		t.Errorf("SourceIP = %q, want 10.0.0.1", sess.SourceIP)
	}
	if sess.Port != 4321 {
		t.Errorf("Port = %d, want 4321", sess.Port)
	}
	if sess.ID == "" {
		t.Error("ID should not be empty")
	}
	if sess.Start.IsZero() {
		t.Error("Start should not be zero")
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
