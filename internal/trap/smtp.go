package trap

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

type SMTPTrap struct {
	cfg      *config.Config
	logger   *slog.Logger
	metrics  *metrics.Metrics
	limiter  *Limiter
	alerter  alert.Alerter
	listener net.Listener
	wg       sync.WaitGroup
}

func NewSMTP(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) *SMTPTrap {
	return &SMTPTrap{
		cfg:     cfg,
		logger:  logger.With("trap", "smtp"),
		metrics: m,
		limiter: limiter,
		alerter: alerter,
	}
}

func (t *SMTPTrap) Start(ctx context.Context) error {
	ln, err := ListenTCP(ctx, t.cfg.TrapAddr("smtp"), t.cfg.ProxyProtocol)
	if err != nil {
		return fmt.Errorf("smtp listen: %w", err)
	}
	t.listener = ln
	t.logger.Info("listening", "addr", t.cfg.TrapAddr("smtp"))

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

func (t *SMTPTrap) Stop(_ context.Context) error {
	if t.listener != nil {
		t.listener.Close()
	}
	t.wg.Wait()
	return nil
}

func (t *SMTPTrap) handle(ctx context.Context, conn net.Conn) {
	defer t.wg.Done()
	defer conn.Close()

	host, port := ParseAddr(conn.RemoteAddr().String())
	sess := NewSession("smtp", host, port)

	if !t.limiter.Acquire(host) {
		t.logger.Warn("connection rejected", "source_ip", host, "reason", "limit_exceeded")
		return
	}
	defer t.limiter.Release(host)

	sess.LogConnect(t.logger)
	sess.RecordStart(t.metrics)
	defer sess.RecordEnd(t.metrics)
	defer sess.LogDisconnect(t.logger)

	_ = conn.SetDeadline(deadlineFromContext(ctx, t.cfg.SessionTimeout))

	if _, err := fmt.Fprintf(conn, "220 mail.example.com ESMTP ready\r\n"); err != nil {
		return
	}

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 512), 512)
	for scanner.Scan() {
		line := scanner.Text()
		cmd := strings.ToUpper(strings.TrimSpace(line))

		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			fmt.Fprintf(conn, "250-mail.example.com\r\n250-AUTH LOGIN PLAIN\r\n250 OK\r\n")
		case strings.HasPrefix(cmd, "HELO"):
			fmt.Fprintf(conn, "250 OK\r\n")
		case strings.HasPrefix(cmd, "AUTH LOGIN"):
			t.handleAuthLogin(ctx, conn, scanner, sess, host)
		case strings.HasPrefix(cmd, "AUTH PLAIN"):
			t.handleAuthPlain(ctx, conn, line, sess, host)
		case strings.HasPrefix(cmd, "MAIL FROM"):
			fmt.Fprintf(conn, "530 5.7.1 Authentication required\r\n")
		case strings.HasPrefix(cmd, "QUIT"):
			fmt.Fprintf(conn, "221 Bye\r\n")
			return
		case strings.HasPrefix(cmd, "NOOP"):
			fmt.Fprintf(conn, "250 OK\r\n")
		case strings.HasPrefix(cmd, "RSET"):
			fmt.Fprintf(conn, "250 OK\r\n")
		default:
			fmt.Fprintf(conn, "502 5.5.2 Command not recognized\r\n")
		}
	}
}

func (t *SMTPTrap) handleAuthLogin(ctx context.Context, conn net.Conn, scanner *bufio.Scanner, sess *Session, host string) {
	fmt.Fprintf(conn, "334 VXNlcm5hbWU6\r\n")
	if !scanner.Scan() {
		return
	}
	userB64 := strings.TrimSpace(scanner.Text())
	userBytes, err := base64.StdEncoding.DecodeString(userB64)
	if err != nil {
		fmt.Fprintf(conn, "501 5.5.4 Invalid base64\r\n")
		return
	}

	fmt.Fprintf(conn, "334 UGFzc3dvcmQ6\r\n")
	if !scanner.Scan() {
		return
	}
	passB64 := strings.TrimSpace(scanner.Text())
	passBytes, err := base64.StdEncoding.DecodeString(passB64)
	if err != nil {
		fmt.Fprintf(conn, "501 5.5.4 Invalid base64\r\n")
		return
	}

	username := string(userBytes)
	password := string(passBytes)

	sess.LogAuthAttempt(t.logger,
		slog.String("username", username),
		slog.String("password", password),
	)
	sess.RecordCredentials(t.metrics)
	t.alerter.Alert(ctx, host, "smtp")

	fmt.Fprintf(conn, "535 5.7.8 Authentication failed\r\n")
}

func (t *SMTPTrap) handleAuthPlain(ctx context.Context, conn net.Conn, line string, sess *Session, host string) {
	// AUTH PLAIN may include the payload inline: AUTH PLAIN <base64>
	parts := strings.SplitN(line, " ", 3)
	var payload string
	if len(parts) == 3 {
		payload = strings.TrimSpace(parts[2])
	}

	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		fmt.Fprintf(conn, "501 5.5.4 Invalid base64\r\n")
		return
	}

	// AUTH PLAIN format: \0username\0password
	fields := bytes.SplitN(decoded, []byte{0}, 3)
	var username, password string
	if len(fields) == 3 {
		username = string(fields[1])
		password = string(fields[2])
	}

	sess.LogAuthAttempt(t.logger,
		slog.String("username", username),
		slog.String("password", password),
	)
	sess.RecordCredentials(t.metrics)
	t.alerter.Alert(ctx, host, "smtp")

	fmt.Fprintf(conn, "535 5.7.8 Authentication failed\r\n")
}
