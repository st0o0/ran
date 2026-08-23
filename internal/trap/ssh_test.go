package trap

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"

	"log/slog"

	gossh "golang.org/x/crypto/ssh"
)

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	return &config.Config{
		Traps:          []string{"ssh"},
		Addrs:          map[string]string{"ssh": addr},
		PerProto:       make(map[string]config.ProtoConfig),
		SSHHostKeyPath: "",
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
		MaxAuthRetries: 3,
	}
}

func TestSSHTrapCaptures(t *testing.T) {
	cfg := testConfig(t)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)
	logger := slog.Default()

	trap, err := NewSSH(cfg, logger, m, limiter, alert.NoopAlerter{})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = trap.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	clientCfg := &gossh.ClientConfig{
		User:            "root",
		Auth:            []gossh.AuthMethod{gossh.Password("admin123")},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	conn, err := gossh.Dial("tcp", cfg.TrapAddr("ssh"), clientCfg)
	if err == nil {
		conn.Close()
	}

	time.Sleep(100 * time.Millisecond)
	cancel()
	_ = trap.Stop(context.Background())
}

func TestSSHHostKeyGeneration(t *testing.T) {
	logger := slog.Default()
	signer, err := loadOrGenerateHostKey("", logger)
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}
	if signer == nil {
		t.Fatal("signer is nil")
	}
	if signer.PublicKey().Type() != "ssh-ed25519" {
		t.Errorf("key type = %s, want ssh-ed25519", signer.PublicKey().Type())
	}
}

func TestSSHBanner(t *testing.T) {
	cfg := testConfig(t)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)
	logger := slog.Default()

	trap, err := NewSSH(cfg, logger, m, limiter, alert.NoopAlerter{})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = trap.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", cfg.TrapAddr("ssh"), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	buf := make([]byte, 256)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	banner := string(buf[:n])
	if len(banner) < 20 || banner[:8] != "SSH-2.0-" {
		t.Errorf("banner = %q, want SSH-2.0-... prefix", banner)
	}

	cancel()
	_ = trap.Stop(context.Background())
}

func TestSSHOutcomeCompletedAfterAuth(t *testing.T) {
	cfg := testConfig(t)
	cfg.MaxAuthRetries = 3
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)
	logger := slog.Default()

	sshTrap, err := NewSSH(cfg, logger, m, limiter, alert.NoopAlerter{})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = sshTrap.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	clientCfg := &gossh.ClientConfig{
		User:            "root",
		Auth:            []gossh.AuthMethod{gossh.Password("test123")},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	conn, err := gossh.Dial("tcp", cfg.TrapAddr("ssh"), clientCfg)
	if err == nil {
		conn.Close()
	}

	time.Sleep(200 * time.Millisecond)

	families, _ := reg.Gather()
	found := false
	for _, f := range families {
		if f.GetName() == "ran_connections_total" {
			for _, m := range f.GetMetric() {
				var proto, outcome string
				for _, l := range m.GetLabel() {
					switch l.GetName() {
					case "protocol":
						proto = l.GetValue()
					case "outcome":
						outcome = l.GetValue()
					}
				}
				if proto == "ssh" && outcome == "completed" && m.GetCounter().GetValue() >= 1 {
					found = true
				}
			}
		}
	}
	if !found {
		t.Error("expected ran_connections_total{protocol=ssh,outcome=completed} >= 1")
	}

	cancel()
	_ = sshTrap.Stop(context.Background())
}

func TestSSHMultiAuth(t *testing.T) {
	cfg := testConfig(t)
	six := 6
	cfg.PerProto["ssh"] = config.ProtoConfig{MaxAuthRetries: &six}
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)
	logger := slog.Default()

	sshTrap, err := NewSSH(cfg, logger, m, limiter, alert.NoopAlerter{})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = sshTrap.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	passwords := []string{"pass1", "pass2", "pass3"}
	idx := 0
	clientCfg := &gossh.ClientConfig{
		User: "root",
		Auth: []gossh.AuthMethod{
			gossh.RetryableAuthMethod(gossh.PasswordCallback(func() (string, error) {
				p := passwords[idx%len(passwords)]
				idx++
				return p, nil
			}), 3),
		},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	conn, err := gossh.Dial("tcp", cfg.TrapAddr("ssh"), clientCfg)
	if err == nil {
		conn.Close()
	}

	time.Sleep(200 * time.Millisecond)

	families, _ := reg.Gather()
	for _, f := range families {
		if f.GetName() == "ran_credentials_captured_total" {
			for _, met := range f.GetMetric() {
				for _, l := range met.GetLabel() {
					if l.GetName() == "protocol" && l.GetValue() == "ssh" {
						if met.GetCounter().GetValue() < 3 {
							t.Errorf("credentials captured = %v, want >= 3", met.GetCounter().GetValue())
						}
					}
				}
			}
		}
	}

	cancel()
	_ = sshTrap.Stop(context.Background())
}
