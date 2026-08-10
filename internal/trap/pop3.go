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

type POP3Trap struct {
	cfg      *config.Config
	logger   *slog.Logger
	metrics  *metrics.Metrics
	limiter  *Limiter
	alerter  alert.Alerter
	listener net.Listener
	wg       sync.WaitGroup
}

func NewPOP3(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) *POP3Trap {
	return &POP3Trap{
		cfg:     cfg,
		logger:  logger.With("trap", "pop3"),
		metrics: m,
		limiter: limiter,
		alerter: alerter,
	}
}

func (t *POP3Trap) Start(ctx context.Context) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", t.cfg.TrapAddr("pop3"))
	if err != nil {
		return fmt.Errorf("pop3 listen: %w", err)
	}
	t.listener = ln
	t.logger.Info("listening", "addr", t.cfg.TrapAddr("pop3"))

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

func (t *POP3Trap) Stop(_ context.Context) error {
	if t.listener != nil {
		t.listener.Close()
	}
	t.wg.Wait()
	return nil
}

func (t *POP3Trap) handle(ctx context.Context, conn net.Conn) {
	defer t.wg.Done()
	defer conn.Close()

	host, port := ParseAddr(conn.RemoteAddr().String())
	sess := NewSession("pop3", host, port)

	if !t.limiter.Acquire(host) {
		t.logger.Warn("connection rejected", "source_ip", host, "reason", "limit_exceeded")
		return
	}
	defer t.limiter.Release(host)

	sess.LogConnect(t.logger)
	sess.RecordStart(t.metrics)
	defer sess.RecordEnd(t.metrics)
	defer sess.LogDisconnect(t.logger)

	conn.SetDeadline(deadlineFromContext(ctx, t.cfg.SessionTimeout))

	if _, err := fmt.Fprint(conn, "+OK POP3 server ready\r\n"); err != nil {
		return
	}

	scanner := bufio.NewScanner(conn)
	var username string

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		upper := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(upper, "USER "):
			username = strings.TrimSpace(line[5:])
			fmt.Fprint(conn, "+OK\r\n")

		case strings.HasPrefix(upper, "PASS "):
			password := strings.TrimSpace(line[5:])
			sess.LogAuthAttempt(t.logger,
				slog.String("username", username),
				slog.String("password", password),
			)
			sess.RecordCredentials(t.metrics)
			t.alerter.Alert(ctx, host, "pop3")
			fmt.Fprint(conn, "-ERR [AUTH] Authentication failed\r\n")

		case strings.HasPrefix(upper, "QUIT"):
			fmt.Fprint(conn, "+OK Bye\r\n")
			return

		default:
			fmt.Fprint(conn, "-ERR Unknown command\r\n")
		}
	}
}
