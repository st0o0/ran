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
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

// Multi-port binding is all or nothing: when one of the telnet default addresses
// cannot be bound, Start fails and nothing is left listening.
func TestTelnetMultiPortBindFailureIsAllOrNothing(t *testing.T) {
	t.Parallel()
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()

	// The first address is free and binds; it must be released again.
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	freeAddr := free.Addr().String()
	free.Close()

	cfg := &config.Config{
		Addrs:          map[string]string{"telnet": freeAddr + "," + busy.Addr().String()},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    10,
		MaxPerIP:       10,
	}
	tr := NewTelnet(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, NewLimiter(10, 10), alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errc := make(chan error, 1)
	go func() { errc <- tr.Start(ctx) }()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("Start succeeded although one address is in use")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return")
	}
	select {
	case <-tr.Ready():
		t.Error("trap reported ready after a failed bind")
	default:
	}
	// The port that did bind is released: nothing accepts there and it can be bound again.
	if c, err := net.DialTimeout("tcp", freeAddr, time.Second); err == nil {
		c.Close()
		t.Errorf("%s still accepts connections after the failed start", freeAddr)
	}
	again, err := net.Listen("tcp", freeAddr)
	if err != nil {
		t.Errorf("%s was not released: %v", freeAddr, err)
	} else {
		again.Close()
	}
}

// Both addresses of a multi-port telnet trap accept connections.
func TestTelnetMultiPortServesBothAddresses(t *testing.T) {
	t.Parallel()
	// Reserve two free ports, release them and bind the trap to both.
	var addrs [2]string
	for i := range addrs {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addrs[i] = l.Addr().String()
		l.Close()
	}
	cfg := testTelnetConfig(addrs[0] + "," + addrs[1])
	tr := NewTelnet(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), metrics.New(prometheus.NewRegistry(), "test"), NewLimiter(10, 10), alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveTrap(t, ctx, tr)
	for _, a := range addrs {
		c := dialTrap(t, a)
		buf := make([]byte, 16)
		if n, err := c.Read(buf); err != nil || n == 0 {
			t.Errorf("no prompt on %s: %d bytes, %v", a, n, err)
		}
	}
}
