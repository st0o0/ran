package trap

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

type MemcachedTrap struct {
	cfg      *config.Config
	logger   *slog.Logger
	metrics  *metrics.Metrics
	limiter  *Limiter
	alerter  alert.Alerter
	listener net.Listener
	wg       sync.WaitGroup
}

func NewMemcached(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) *MemcachedTrap {
	return &MemcachedTrap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
		limiter: limiter,
		alerter: alerter,
	}
}

func (t *MemcachedTrap) Start(ctx context.Context) error {
	ln, err := ListenTCP(ctx, t.cfg.TrapAddr("memcached"), t.cfg.ProxyProtocol)
	if err != nil {
		return fmt.Errorf("memcached listen: %w", err)
	}
	t.listener = ln
	t.logger.Info("listening", "addr", t.cfg.TrapAddr("memcached"))

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			t.logger.Debug("accept error", "error", err)
			continue
		}
		t.wg.Add(1)
		go t.handle(ctx, conn)
	}
	return nil
}

func (t *MemcachedTrap) Stop(_ context.Context) error {
	if t.listener != nil {
		t.listener.Close()
	}
	t.wg.Wait()
	return nil
}

func (t *MemcachedTrap) handle(ctx context.Context, conn net.Conn) {
	defer t.wg.Done()
	defer conn.Close()

	host, port := ParseAddr(conn.RemoteAddr().String())
	_, destPort := ParseAddr(t.listener.Addr().String())
	sess := NewSession("memcached", host, port, destPort, t.logger)

	if !t.limiter.Acquire(host) {
		t.logger.Warn("connection rejected", "source_ip", host, "reason", "limit_exceeded")
		return
	}
	defer t.limiter.Release(host)

	sess.LogConnect()
	sess.RecordStart(t.metrics)
	defer sess.RecordEnd(t.metrics)
	defer sess.LogDisconnect()

	_ = conn.SetDeadline(deadlineFromContext(ctx, t.cfg.SessionTimeout))
	t.alerter.Alert(ctx, host, "memcached", nil)

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 4096), 4096)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if strings.ToLower(strings.TrimSpace(line)) == "quit" {
			return
		}
		sess.LogCommand(line)
		fmt.Fprint(conn, "ERROR\r\n")
	}
}
