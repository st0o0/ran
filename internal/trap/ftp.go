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

type FTPTrap struct {
	cfg      *config.Config
	logger   *slog.Logger
	metrics  *metrics.Metrics
	limiter  *Limiter
	alerter  alert.Alerter
	listener net.Listener
	wg       sync.WaitGroup
}

func NewFTP(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) *FTPTrap {
	return &FTPTrap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
		limiter: limiter,
		alerter: alerter,
	}
}

func (t *FTPTrap) Start(ctx context.Context) error {
	ln, err := ListenTCP(ctx, t.cfg.TrapAddr("ftp"), t.cfg.ProxyProtocol)
	if err != nil {
		return fmt.Errorf("ftp listen: %w", err)
	}
	t.listener = ln
	t.logger.Info("listening", "addr", t.cfg.TrapAddr("ftp"))

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

func (t *FTPTrap) Stop(_ context.Context) error {
	if t.listener != nil {
		t.listener.Close()
	}
	t.wg.Wait()
	return nil
}

func (t *FTPTrap) handle(ctx context.Context, conn net.Conn) {
	defer t.wg.Done()
	defer conn.Close()

	host, port := ParseAddr(conn.RemoteAddr().String())
	_, destPort := ParseAddr(t.listener.Addr().String())
	sess := NewSession("ftp", host, port, destPort, t.logger)

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

	if _, err := fmt.Fprint(conn, "220 FTP Server ready.\r\n"); err != nil {
		return
	}

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 512), 512)
	var username string

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		upper := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(upper, "USER "):
			username = strings.TrimSpace(line[5:])
			fmt.Fprint(conn, "331 Password required.\r\n")

		case strings.HasPrefix(upper, "PASS "):
			password := strings.TrimSpace(line[5:])
			sess.LogAuthAttempt(
				slog.String("username", username),
				slog.String("password", password),
			)
			sess.RecordCredentials(t.metrics)
			t.alerter.Alert(ctx, host, "ftp")
			fmt.Fprint(conn, "530 Login incorrect.\r\n")

		case strings.HasPrefix(upper, "QUIT"):
			fmt.Fprint(conn, "221 Goodbye.\r\n")
			return

		default:
			fmt.Fprint(conn, "530 Please login with USER and PASS.\r\n")
		}
	}
}
