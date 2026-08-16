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

type IRCTrap struct {
	cfg      *config.Config
	logger   *slog.Logger
	metrics  *metrics.Metrics
	limiter  *Limiter
	alerter  alert.Alerter
	listener net.Listener
	wg       sync.WaitGroup
}

func NewIRC(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) *IRCTrap {
	return &IRCTrap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
		limiter: limiter,
		alerter: alerter,
	}
}

func (t *IRCTrap) Start(ctx context.Context) error {
	ln, err := ListenTCP(ctx, t.cfg.TrapAddr("irc"), t.cfg.ProxyProtocol)
	if err != nil {
		return fmt.Errorf("irc listen: %w", err)
	}
	t.listener = ln
	t.logger.Info("listening", "addr", t.cfg.TrapAddr("irc"))

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

func (t *IRCTrap) Stop(_ context.Context) error {
	if t.listener != nil {
		t.listener.Close()
	}
	t.wg.Wait()
	return nil
}

func (t *IRCTrap) handle(ctx context.Context, conn net.Conn) {
	defer t.wg.Done()
	defer conn.Close()

	host, port := ParseAddr(conn.RemoteAddr().String())
	_, destPort := ParseAddr(t.listener.Addr().String())
	sess := NewSession("irc", host, port, destPort, t.logger)

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

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 512), 512)
	var nick string
	registered := false

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, " ", 2)
		cmd := strings.ToUpper(parts[0])
		params := ""
		if len(parts) > 1 {
			params = parts[1]
		}

		switch cmd {
		case "PASS":
			password := strings.TrimPrefix(params, ":")
			sess.LogAuthAttempt(
				slog.String("username", nick),
				slog.String("password", password),
			)
			sess.RecordCredentials(t.metrics)
			t.alerter.Alert(ctx, host, "irc", map[string]string{"username": nick, "password": password})

		case "NICK":
			nick = strings.TrimPrefix(params, ":")
			if registered {
				continue
			}

		case "USER":
			if !registered {
				registered = true
				if nick == "" {
					nick = "*"
				}
				fmt.Fprintf(conn, ":server 001 %s :Welcome to the IRC Network\r\n", nick)
			}

		case "QUIT":
			fmt.Fprintf(conn, "ERROR :Closing Link: %s (Quit)\r\n", host)
			return

		case "PING":
			fmt.Fprintf(conn, "PONG %s\r\n", params)

		default:
			sess.LogCommand(line)
		}
	}
}
