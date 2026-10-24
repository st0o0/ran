package trap

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/metrics"
	gossh "golang.org/x/crypto/ssh"
)

func TestSSHMaxAuthTriesMapping(t *testing.T) {
	t.Parallel()
	// x/crypto turns 0 into 6 and treats negative values as unlimited.
	if got := sshMaxAuthTries(0); got >= 0 {
		t.Errorf("sshMaxAuthTries(0) = %d, want a negative (unlimited) value", got)
	}
	if got := sshMaxAuthTries(3); got != 3 {
		t.Errorf("sshMaxAuthTries(3) = %d, want 3", got)
	}
}

func counterSum(t *testing.T, reg *prometheus.Registry, name, label, value string) float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var sum float64
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == label && l.GetValue() == value {
					sum += m.GetCounter().GetValue()
				}
			}
		}
	}
	return sum
}

func TestSSHZeroRetriesIsUnlimited(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	cfg.MaxAuthRetries = 0
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	sshTrap, err := NewSSH(cfg, slog.Default(), m, NewLimiter(cfg.MaxSessions, cfg.MaxPerIP), alert.NoopAlerter{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := serveTrap(t, ctx, sshTrap)

	const attempts = 9 // more than the x/crypto default of 6
	n := 0
	clientCfg := &gossh.ClientConfig{
		User: "root",
		Auth: []gossh.AuthMethod{
			gossh.RetryableAuthMethod(gossh.PasswordCallback(func() (string, error) {
				n++
				return "pw", nil
			}), attempts),
		},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}
	if c, err := gossh.Dial("tcp", addr, clientCfg); err == nil {
		c.Close()
	}

	waitUntil(t, func() bool {
		return counterSum(t, reg, "ran_credentials_captured_total", "protocol", "ssh") >= attempts
	})
}

func TestTarpitDurationCapsAtSessionTimeout(t *testing.T) {
	t.Parallel()
	if d, capped := tarpitDuration(5*time.Second, 30*time.Second); d != 5*time.Second || capped {
		t.Errorf("shorter tarpit = %v, %v; want 5s, false", d, capped)
	}
	for _, duration := range []time.Duration{30 * time.Second, time.Minute} {
		d, capped := tarpitDuration(duration, 30*time.Second)
		if !capped || d >= 30*time.Second || d < 29*time.Second {
			t.Errorf("tarpit %v vs 30s timeout = %v, %v; want just below 30s, capped", duration, d, capped)
		}
	}
	if d, capped := tarpitDuration(time.Second, time.Second); !capped || d <= 0 || d >= time.Second {
		t.Errorf("1s vs 1s = %v, %v; want a positive duration below 1s, capped", d, capped)
	}
}

func TestSSHTarpitZeroDurationReturnsAtOnce(t *testing.T) {
	t.Parallel()
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	if err := sshTarpit(context.Background(), server, 0); err != nil {
		t.Fatalf("zero duration tarpit = %v, want nil", err)
	}
}

// With the default settings (tarpit duration equal to the session timeout) the
// tarpit must end cleanly before the connection deadline: outcome timeout, not error.
func TestSSHTarpitAtSessionTimeoutEndsCleanly(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	cfg.SSHTarpit = true
	cfg.SessionTimeout = time.Second
	cfg.SSHTarpitDuration = time.Second
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	sshTrap, err := NewSSH(cfg, slog.Default(), m, NewLimiter(cfg.MaxSessions, cfg.MaxPerIP), alert.NoopAlerter{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := serveTrap(t, ctx, sshTrap)

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	data, _ := io.ReadAll(conn)
	if len(data) != 34 {
		t.Errorf("tarpit sent %d bytes, want one 32 character line plus CRLF", len(data))
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("connection stayed open for %v, want it closed near the session timeout", d)
	}

	waitUntil(t, func() bool {
		return counterSum(t, reg, "ran_connections_total", "outcome", "timeout") >= 1
	})
	if got := counterSum(t, reg, "ran_connections_total", "outcome", "error"); got != 0 {
		t.Errorf("error outcomes = %v, want 0", got)
	}
}
