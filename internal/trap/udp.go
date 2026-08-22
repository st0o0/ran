package trap

import (
	"context"
	"log/slog"
	"net"
	"sync"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/metrics"
)

type PacketHandler interface {
	HandlePacket(ctx context.Context, sess *Session, data []byte, respond func([]byte))
}

type UDPTrap struct {
	protocol string
	addrs    []string
	logger   *slog.Logger
	metrics  *metrics.Metrics
	limiter  *Limiter
	alerter  alert.Alerter
	handler  PacketHandler
	conns    []net.PacketConn
	wg       sync.WaitGroup
}

func NewUDP(protocol string, addrs []string, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter, handler PacketHandler) *UDPTrap {
	return &UDPTrap{
		protocol: protocol,
		addrs:    addrs,
		logger:   logger,
		metrics:  m,
		limiter:  limiter,
		alerter:  alerter,
		handler:  handler,
	}
}

func (t *UDPTrap) Start(ctx context.Context) error {
	var lc net.ListenConfig
	for _, addr := range t.addrs {
		conn, err := lc.ListenPacket(ctx, "udp", addr)
		if err != nil {
			for _, c := range t.conns {
				c.Close()
			}
			return err
		}
		t.conns = append(t.conns, conn)
		t.logger.Info("listening", "addr", addr)
	}

	go func() {
		<-ctx.Done()
		for _, c := range t.conns {
			c.Close()
		}
	}()

	for _, conn := range t.conns {
		go t.readLoop(ctx, conn)
	}

	<-ctx.Done()
	return nil
}

func (t *UDPTrap) readLoop(ctx context.Context, conn net.PacketConn) {
	_, destPort := ParseAddr(conn.LocalAddr().String())
	buf := make([]byte, 4096)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			t.logger.Debug("read error", "error", err)
			continue
		}

		host, port := ParseAddr(addr.String())
		if !t.limiter.Acquire(host) {
			LogRejected(t.logger, t.protocol, "udp", destPort, host, "rate_limit")
			continue
		}

		sess := NewSession(t.protocol, "udp", host, port, destPort, t.logger)
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
			t.handler.HandlePacket(ctx, sess, data, respond)
		}()
	}
}

func (t *UDPTrap) Stop(_ context.Context) error {
	for _, c := range t.conns {
		c.Close()
	}
	t.wg.Wait()
	return nil
}
