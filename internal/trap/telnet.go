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

type TelnetTrap struct {
	cfg      *config.Config
	logger   *slog.Logger
	metrics  *metrics.Metrics
	limiter  *Limiter
	alerter  alert.Alerter
	listener *MultiListener
	wg       sync.WaitGroup
}

func NewTelnet(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) *TelnetTrap {
	return &TelnetTrap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
		limiter: limiter,
		alerter: alerter,
	}
}

func (t *TelnetTrap) Start(ctx context.Context) error {
	ln, err := ListenMultiTCP(ctx, t.cfg.TrapAddrs("telnet"), t.cfg.ProxyProtocol)
	if err != nil {
		return fmt.Errorf("telnet listen: %w", err)
	}
	t.listener = ln
	t.logger.Info("listening", "addrs", t.cfg.TrapAddrs("telnet"))

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
			LogErrorStandalone(t.logger, "telnet", "accept_failed", err)
			continue
		}
		t.wg.Add(1)
		go t.handle(ctx, conn)
	}
	return nil
}

func (t *TelnetTrap) Stop(_ context.Context) error {
	if t.listener != nil {
		t.listener.Close()
	}
	t.wg.Wait()
	return nil
}

func (t *TelnetTrap) handle(ctx context.Context, conn net.Conn) {
	defer t.wg.Done()
	defer conn.Close()

	host, port := ParseAddr(conn.RemoteAddr().String())
	_, destPort := ParseAddr(conn.LocalAddr().String())
	sess := NewSession("telnet", "tcp", host, port, destPort, t.logger)

	if !t.limiter.Acquire(host) {
		LogRejected(t.logger, "telnet", "tcp", destPort, host, "rate_limit")
		return
	}
	defer t.limiter.Release(host)

	sess.LogConnect()
	sess.RecordStart(t.metrics)
	defer sess.RecordEnd(t.metrics)
	defer sess.LogDisconnect()

	_ = conn.SetDeadline(deadlineFromContext(ctx, t.cfg.SessionTimeout))

	reader := bufio.NewReaderSize(conn, 4096)

	fmt.Fprint(conn, "\r\nLogin: ")
	userLine, err := reader.ReadString('\n')
	if err != nil {
		if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() {
			sess.SetOutcome("timeout")
		} else {
			sess.SetOutcome("error")
		}
		return
	}
	username := strings.TrimSpace(userLine)

	fmt.Fprint(conn, "Password: ")
	passLine, err := reader.ReadString('\n')
	if err != nil {
		if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() {
			sess.SetOutcome("timeout")
		} else {
			sess.SetOutcome("error")
		}
		return
	}
	password := strings.TrimSpace(passLine)

	sess.LogAuthAttempt(
		slog.String("username", username),
		slog.String("password", password),
	)
	sess.RecordCredentials(t.metrics)
	t.alerter.Alert(ctx, host, "telnet", map[string]string{"username": username, "password": password})

	fmt.Fprint(conn, "\r\nLogin incorrect\r\n")
}
