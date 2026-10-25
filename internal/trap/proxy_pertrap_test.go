package trap

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

func perTrapConfig(trusted string) *config.Config {
	return &config.Config{
		Addrs:          map[string]string{"telnet": "127.0.0.1:0", "ftp": "127.0.0.1:0"},
		PerProto:       make(map[string]config.ProtoConfig),
		ProxyTraps:     map[string]bool{"telnet": true},
		ProxyTrusted:   []netip.Prefix{netip.MustParsePrefix(trusted)},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
		MaxAuthRetries: 1,
	}
}

// RAN_PROXY_PROTOCOL=telnet: the telnet trap requires a PROXY header from a
// trusted peer, the ftp trap in the same process serves direct connections.
func TestProxyProtocolMixedDeployment(t *testing.T) {
	cfg := perTrapConfig("127.0.0.1/32")
	logs := &syncBuffer{}
	logger := newJSONLogger(logs)
	m := metrics.New(prometheus.NewRegistry(), "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)
	rec := &recordingAlerter{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proxied := serveTrap(t, ctx, NewTelnet(cfg, logger, m, limiter, rec))
	direct := serveTrap(t, ctx, NewFTP(cfg, logger, m, limiter, rec))

	// Direct trap: no header, served, the source is the socket peer.
	dc, err := net.DialTimeout("tcp", direct, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer dc.Close()
	_ = dc.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(dc).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "220 ") {
		t.Fatalf("direct trap greeting = %q, err %v", line, err)
	}
	fmt.Fprint(dc, "QUIT\r\n")

	// Proxied trap, no header: dropped without being served.
	nc, err := net.DialTimeout("tcp", proxied, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	fmt.Fprint(nc, "root\r\n")
	expectClosed(t, nc, 5*time.Second)
	waitFor(t, func() bool { return proxyDropped(t, m, "telnet") == 1 })
	if n := proxyDropped(t, m, "ftp"); n != 0 {
		t.Errorf("ftp proxy drops = %v, want 0", n)
	}

	// Proxied trap, valid header from the trusted peer: served, the source is
	// the address from the header.
	pc, err := net.DialTimeout("tcp", proxied, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(pc, "PROXY TCP4 9.9.9.9 1.1.1.1 40000 23\r\n")
	prompt := make([]byte, len("\r\nLogin: "))
	if _, err := pc.Read(prompt); err != nil || !strings.Contains(string(prompt), "Login:") {
		t.Fatalf("proxied trap prompt = %q, err %v", prompt, err)
	}
	_ = pc.Close()
	_ = dc.Close()
	waitFor(t, func() bool {
		s := logs.String()
		return strings.Contains(s, "9.9.9.9") && strings.Contains(s, "127.0.0.1")
	})
	if proxyDropped(t, m, "telnet") != 1 {
		t.Errorf("telnet proxy drops = %v, want 1", proxyDropped(t, m, "telnet"))
	}
}

// An untrusted peer on the proxied trap is dropped before the header is read,
// while the direct trap is unaffected.
func TestProxyProtocolPerTrapUntrustedPeer(t *testing.T) {
	cfg := perTrapConfig("10.0.0.0/8")
	logger := newJSONLogger(&syncBuffer{})
	m := metrics.New(prometheus.NewRegistry(), "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)
	rec := &recordingAlerter{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proxied := serveTrap(t, ctx, NewTelnet(cfg, logger, m, limiter, rec))
	direct := serveTrap(t, ctx, NewFTP(cfg, logger, m, limiter, rec))

	c, err := net.DialTimeout("tcp", proxied, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprint(c, "PROXY TCP4 8.8.8.8 1.1.1.1 40000 23\r\n")
	expectClosed(t, c, 5*time.Second)
	waitFor(t, func() bool { return proxyDropped(t, m, "telnet") == 1 })

	dc, err := net.DialTimeout("tcp", direct, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer dc.Close()
	_ = dc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if line, err := bufio.NewReader(dc).ReadString('\n'); err != nil || !strings.HasPrefix(line, "220 ") {
		t.Fatalf("direct trap greeting = %q, err %v", line, err)
	}
	if n := len(rec.snapshot()); n != 0 {
		t.Errorf("alerts = %d, want 0", n)
	}
}
