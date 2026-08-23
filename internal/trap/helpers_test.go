package trap

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestAuthSleepZeroDelay(t *testing.T) {
	ctx := context.Background()
	start := time.Now()
	err := authSleep(ctx, 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Error("zero delay should return immediately")
	}
}

func TestAuthSleepEscalation(t *testing.T) {
	ctx := context.Background()
	base := 50 * time.Millisecond

	for _, tc := range []struct {
		attempt    int
		wantMin    time.Duration
		wantMax    time.Duration
	}{
		{0, 50 * time.Millisecond, 100 * time.Millisecond},
		{1, 100 * time.Millisecond, 150 * time.Millisecond},
		{2, 200 * time.Millisecond, 250 * time.Millisecond},
	} {
		start := time.Now()
		_ = authSleep(ctx, base, tc.attempt)
		elapsed := time.Since(start)
		if elapsed < tc.wantMin || elapsed > tc.wantMax {
			t.Errorf("attempt %d: elapsed %v, want %v-%v", tc.attempt, elapsed, tc.wantMin, tc.wantMax)
		}
	}
}

func TestAuthSleepCap(t *testing.T) {
	ctx := context.Background()
	base := 50 * time.Millisecond

	start := time.Now()
	_ = authSleep(ctx, base, 5)
	elapsed := time.Since(start)
	// capped at 4× base = 200ms
	if elapsed < 190*time.Millisecond || elapsed > 260*time.Millisecond {
		t.Errorf("attempt 5 (capped): elapsed %v, want ~200ms", elapsed)
	}
}

func TestAuthSleepContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := authSleep(ctx, 10*time.Second, 0)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected context error")
	}
	if elapsed > 200*time.Millisecond {
		t.Errorf("should have returned quickly after cancel, took %v", elapsed)
	}
}

func TestSSHTarpitLineFormat(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	go func() {
		_ = sshTarpit(ctx, server, 300*time.Millisecond)
		server.Close()
	}()

	reader := bufio.NewReader(client)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) != 32 {
		t.Errorf("line length = %d, want 32", len(line))
	}
	for _, c := range line {
		if c < '!' || c > '~' {
			t.Errorf("non-printable character: %q", c)
		}
	}
	if strings.HasPrefix(line, "SSH-") {
		t.Error("tarpit line must not start with SSH-")
	}
}

func TestSSHTarpitDuration(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := client.Read(buf); err != nil {
				return
			}
		}
	}()

	ctx := context.Background()
	start := time.Now()
	_ = sshTarpit(ctx, server, 200*time.Millisecond)
	elapsed := time.Since(start)
	server.Close()

	if elapsed < 190*time.Millisecond {
		t.Errorf("tarpit ended too early: %v", elapsed)
	}
}

func TestSSHTarpitClientDisconnect(t *testing.T) {
	server, client := net.Pipe()

	ctx := context.Background()
	done := make(chan error, 1)
	go func() {
		done <- sshTarpit(ctx, server, 10*time.Second)
	}()

	client.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected write error after client disconnect")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("tarpit did not detect client disconnect")
	}
	server.Close()
}
