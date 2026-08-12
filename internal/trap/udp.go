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
	HandlePacket(ctx context.Context, src net.Addr, data []byte, respond func([]byte))
}

type UDPTrap struct {
	protocol string
	addr     string
	destPort int
	logger   *slog.Logger
	metrics  *metrics.Metrics
	limiter  *Limiter
	alerter  alert.Alerter
	handler  PacketHandler
	conn     net.PacketConn
	wg       sync.WaitGroup
}

func NewUDP(protocol, addr string, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter, handler PacketHandler) *UDPTrap {
	_, dp := ParseAddr(addr)
	return &UDPTrap{
		protocol: protocol,
		addr:     addr,
		destPort: dp,
		logger:   logger,
		metrics:  m,
		limiter:  limiter,
		alerter:  alerter,
		handler:  handler,
	}
}

func (t *UDPTrap) Start(ctx context.Context) error {
	var lc net.ListenConfig
	conn, err := lc.ListenPacket(ctx, "udp", t.addr)
	if err != nil {
		return err
	}
	t.conn = conn
	t.logger.Info("listening", "addr", t.addr)

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	buf := make([]byte, 4096)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			t.logger.Debug("read error", "error", err)
			continue
		}

		host, port := ParseAddr(addr.String())
		if !t.limiter.Acquire(host) {
			t.logger.Warn("packet rejected", "source_ip", host, "reason", "limit_exceeded")
			continue
		}

		sess := NewSession(t.protocol, host, port, t.destPort, t.logger)
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
			t.handler.HandlePacket(ctx, addr, data, respond)
		}()
	}
	return nil
}

func (t *UDPTrap) Stop(_ context.Context) error {
	if t.conn != nil {
		t.conn.Close()
	}
	t.wg.Wait()
	return nil
}
