package trap

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

type PacketHandler interface {
	HandlePacket(ctx context.Context, sess *Session, data []byte, respond func([]byte))
}

type UDPTrap struct {
	*bound
	protocol string
	addrs    []string
	logger   *slog.Logger
	metrics  *metrics.Metrics
	limiter  *Limiter
	rate     *udpRateLimiter
	handler  PacketHandler
	// ignore reports sources in RAN_IGNORE_IPS. UDP never alerts, so it only
	// marks the session log and counts it; nil means no ignore list.
	ignore func(ip string) bool

	mu      sync.Mutex
	conns    []net.PacketConn
	stopping bool
	done     chan struct{}
	wg       sync.WaitGroup
}

func NewUDP(protocol string, addrs []string, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, rate *udpRateLimiter, handler PacketHandler) *UDPTrap {
	return &UDPTrap{
		bound:    newBound(),
		done:     make(chan struct{}),
		protocol: protocol,
		addrs:    addrs,
		logger:   logger,
		metrics:  m,
		limiter:  limiter,
		rate:     rate,
		handler:  handler,
	}
}

func (t *UDPTrap) Start(ctx context.Context) error {
	var lc net.ListenConfig
	conns := make([]net.PacketConn, 0, len(t.addrs))
	for _, addr := range t.addrs {
		conn, err := lc.ListenPacket(ctx, "udp", addr)
		if err != nil {
			for _, c := range conns {
				c.Close()
			}
			return err
		}
		conns = append(conns, conn)
		t.logger.Info("listening", "addr", addr)
	}

	t.mu.Lock()
	if t.stopping {
		t.mu.Unlock()
		if len(conns) > 0 {
			t.set(conns[0].LocalAddr()) // keep Ready from hanging
		}
		for _, c := range conns {
			c.Close()
		}
		return nil
	}
	t.conns = conns
	// Add before the goroutines exist, ordered against Stop by the mutex.
	t.wg.Add(len(conns))
	t.mu.Unlock()

	if len(conns) > 0 {
		t.set(conns[0].LocalAddr())
	}

	stop := context.AfterFunc(ctx, func() {
		for _, c := range conns {
			c.Close()
		}
	})
	defer stop()

	for _, conn := range conns {
		go func() {
			defer t.wg.Done()
			t.readLoop(ctx, conn)
		}()
	}

	select {
	case <-ctx.Done():
	case <-t.done:
	}
	return nil
}

func (t *UDPTrap) readLoop(ctx context.Context, conn net.PacketConn) {
	_, destPort := ParseAddr(conn.LocalAddr().String())
	buf := make([]byte, 4096)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			t.logger.Debug("read error", "error", err)
			continue
		}

		host, port := ParseAddr(addr.String())
		// Drop floods before a session or goroutine exists; debug only to avoid log amplification.
		if !t.rate.Allow(host) {
			if t.metrics != nil {
				t.metrics.UDPRateLimited.WithLabelValues(t.protocol).Inc()
			}
			t.logger.Debug("udp packet dropped", "protocol", t.protocol, "source_ip", host, "reason", "packet_rate")
			continue
		}

		if !t.limiter.Acquire(host) {
			LogRejected(t.logger, t.metrics, t.protocol, alert.TransportUDP, destPort, host, "rate_limit")
			continue
		}

		sess := NewSession(t.protocol, alert.TransportUDP, host, port, destPort, t.logger)
		if t.ignore != nil && t.ignore(host) {
			sess.markIgnored()
		}
		sess.LogConnect()
		sess.RecordStart(t.metrics)

		data := make([]byte, n)
		copy(data, buf[:n])

		respond := func(resp []byte) {
			_, _ = conn.WriteTo(resp, addr)
		}

		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			defer t.limiter.Release(host)
			defer sess.RecordEnd(t.metrics)
			defer sess.LogDisconnect()
			safely(t.logger, t.metrics, t.protocol, func() {
				t.handler.HandlePacket(ctx, sess, data, respond)
			})
		}()
	}
}

// Stop closes the sockets and waits for read loops and packet handlers. It
// returns ctx.Err() if they do not finish before ctx ends and may be called
// repeatedly.
func (t *UDPTrap) Stop(ctx context.Context) error {
	t.mu.Lock()
	if !t.stopping {
		t.stopping = true
		close(t.done)
	}
	conns := t.conns
	t.mu.Unlock()

	for _, c := range conns {
		c.Close()
	}

	waited := make(chan struct{})
	go func() {
		t.wg.Wait()
		close(waited)
	}()
	select {
	case <-waited:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// withIgnore wires the RAN_IGNORE_IPS list of cfg into the trap.
func (t *UDPTrap) withIgnore(cfg *config.Config) *UDPTrap {
	if len(cfg.IgnoreIPs) > 0 {
		t.ignore = cfg.IsIgnored
	}
	return t
}
