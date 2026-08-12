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

type IMAPTrap struct {
	cfg      *config.Config
	logger   *slog.Logger
	metrics  *metrics.Metrics
	limiter  *Limiter
	alerter  alert.Alerter
	listener net.Listener
	wg       sync.WaitGroup
}

func NewIMAP(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) *IMAPTrap {
	return &IMAPTrap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
		limiter: limiter,
		alerter: alerter,
	}
}

func (t *IMAPTrap) Start(ctx context.Context) error {
	ln, err := ListenTCP(ctx, t.cfg.TrapAddr("imap"), t.cfg.ProxyProtocol)
	if err != nil {
		return fmt.Errorf("imap listen: %w", err)
	}
	t.listener = ln
	t.logger.Info("listening", "addr", t.cfg.TrapAddr("imap"))

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

func (t *IMAPTrap) Stop(_ context.Context) error {
	if t.listener != nil {
		t.listener.Close()
	}
	t.wg.Wait()
	return nil
}

func (t *IMAPTrap) handle(ctx context.Context, conn net.Conn) {
	defer t.wg.Done()
	defer conn.Close()

	host, port := ParseAddr(conn.RemoteAddr().String())
	_, destPort := ParseAddr(t.listener.Addr().String())
	sess := NewSession("imap", host, port, destPort, t.logger)

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

	if _, err := fmt.Fprint(conn, "* OK IMAP4rev1 Server Ready\r\n"); err != nil {
		return
	}

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 1024), 1024)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 2 {
			continue
		}
		tag := parts[0]
		cmd := strings.ToUpper(parts[1])
		rest := ""
		if len(parts) > 2 {
			rest = parts[2]
		}

		switch cmd {
		case "LOGIN":
			fields := strings.SplitN(rest, " ", 2)
			username := ""
			password := ""
			if len(fields) >= 1 {
				username = strings.Trim(fields[0], "\"")
			}
			if len(fields) >= 2 {
				password = strings.Trim(fields[1], "\"")
			}
			sess.LogAuthAttempt(
				slog.String("username", username),
				slog.String("password", password),
			)
			sess.RecordCredentials(t.metrics)
			t.alerter.Alert(ctx, host, "imap")
			fmt.Fprintf(conn, "%s NO [AUTHENTICATIONFAILED] Invalid credentials\r\n", tag)

		case "CAPABILITY":
			fmt.Fprintf(conn, "* CAPABILITY IMAP4rev1 AUTH=PLAIN LOGIN STARTTLS\r\n%s OK CAPABILITY completed\r\n", tag)

		case "LOGOUT":
			fmt.Fprintf(conn, "* BYE IMAP4rev1 Server logging out\r\n%s OK LOGOUT completed\r\n", tag)
			return

		case "NOOP":
			fmt.Fprintf(conn, "%s OK NOOP completed\r\n", tag)

		default:
			sess.LogCommand(line)
			fmt.Fprintf(conn, "%s BAD Unknown command\r\n", tag)
		}
	}
}
