package trap

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

func testTelnetConfig(addr string) *config.Config {
	return &config.Config{
		Addrs:          map[string]string{"telnet": addr},
		PerProto:       make(map[string]config.ProtoConfig),
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
		MaxAuthRetries: 3,
	}
}

func TestTelnetTrapConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := testTelnetConfig(addr)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewTelnet(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
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

	reader := bufio.NewReader(conn)

	line, err := reader.ReadString(':')
	if err != nil {
		t.Fatal(err)
	}
	if line != "\r\nLogin:" {
		t.Errorf("login prompt = %q, want %q", line, "\r\nLogin:")
	}
	// consume trailing space
	b, _ := reader.ReadByte()
	if b != ' ' {
		t.Errorf("expected space after Login:, got %q", b)
	}

	fmt.Fprint(conn, "root\r\n")

	line, err = reader.ReadString(':')
	if err != nil {
		t.Fatal(err)
	}
	if line != "Password:" {
		t.Errorf("password prompt = %q, want %q", line, "Password:")
	}
	b, _ = reader.ReadByte()
	if b != ' ' {
		t.Errorf("expected space after Password:, got %q", b)
	}

	fmt.Fprint(conn, "toor\r\n")

	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	// Read second line
	line2, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	combined := line + line2
	if combined != "\r\n" + "Login incorrect\r\n" {
		t.Errorf("response = %q, want %q", combined, "\r\nLogin incorrect\r\n")
	}

	cancel()
	_ = trap.Stop(context.Background())
}

func TestTelnetMultiAttempt(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := testTelnetConfig(addr)
	cfg.MaxAuthRetries = 2
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	telnetTrap := NewTelnet(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = telnetTrap.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	reader := bufio.NewReader(conn)

	for i := 0; i < 2; i++ {
		_, _ = reader.ReadString(':')
		_, _ = reader.ReadByte()
		fmt.Fprintf(conn, "user%d\r\n", i)

		_, _ = reader.ReadString(':')
		_, _ = reader.ReadByte()
		fmt.Fprintf(conn, "pass%d\r\n", i)

		_, _ = reader.ReadString('\n')
		_, _ = reader.ReadString('\n')
	}

	time.Sleep(200 * time.Millisecond)

	families, _ := reg.Gather()
	for _, f := range families {
		if f.GetName() == "ran_credentials_captured_total" {
			for _, met := range f.GetMetric() {
				for _, l := range met.GetLabel() {
					if l.GetName() == "protocol" && l.GetValue() == "telnet" {
						if met.GetCounter().GetValue() != 2 {
							t.Errorf("credentials captured = %v, want 2", met.GetCounter().GetValue())
						}
					}
				}
			}
		}
	}

	cancel()
	_ = telnetTrap.Stop(context.Background())
}
