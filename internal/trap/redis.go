package trap

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

type RedisTrap struct {
	cfg      *config.Config
	logger   *slog.Logger
	metrics  *metrics.Metrics
	limiter  *Limiter
	alerter  alert.Alerter
	listener net.Listener
	wg       sync.WaitGroup
}

func NewRedis(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) *RedisTrap {
	return &RedisTrap{
		cfg:     cfg,
		logger:  logger.With("trap", "redis"),
		metrics: m,
		limiter: limiter,
		alerter: alerter,
	}
}

func (t *RedisTrap) Start(ctx context.Context) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", t.cfg.TrapAddr("redis"))
	if err != nil {
		return fmt.Errorf("redis listen: %w", err)
	}
	t.listener = ln
	t.logger.Info("listening", "addr", t.cfg.TrapAddr("redis"))

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

func (t *RedisTrap) Stop(_ context.Context) error {
	if t.listener != nil {
		t.listener.Close()
	}
	t.wg.Wait()
	return nil
}

func (t *RedisTrap) handle(ctx context.Context, conn net.Conn) {
	defer t.wg.Done()
	defer conn.Close()

	host, port := ParseAddr(conn.RemoteAddr().String())
	sess := NewSession("redis", host, port)

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

	reader := bufio.NewReaderSize(conn, 4096)

	for {
		args, err := readRedisCommand(reader)
		if err != nil {
			return
		}
		if len(args) == 0 {
			continue
		}

		cmd := strings.ToUpper(args[0])
		switch cmd {
		case "AUTH":
			password := ""
			if len(args) > 1 {
				password = args[1]
			}
			sess.LogAuthAttempt(t.logger,
				slog.String("username", ""),
				slog.String("password", password),
			)
			sess.RecordCredentials(t.metrics)
			t.alerter.Alert(ctx, host, "redis")
			fmt.Fprint(conn, "-ERR invalid password\r\n")

		case "QUIT":
			fmt.Fprint(conn, "+OK\r\n")
			return

		default:
			sess.LogCommand(t.logger, strings.Join(args, " "))
			fmt.Fprint(conn, "-NOAUTH Authentication required.\r\n")
		}
	}
}

func readRedisCommand(reader *bufio.Reader) ([]string, error) {
	b, err := reader.Peek(1)
	if err != nil {
		return nil, err
	}

	if b[0] == '*' {
		return readRESPArray(reader)
	}
	return readInlineCommand(reader)
}

func readRESPArray(reader *bufio.Reader) ([]string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")

	count, err := strconv.Atoi(line[1:])
	if err != nil || count < 0 {
		return nil, fmt.Errorf("invalid RESP array count: %s", line)
	}

	args := make([]string, 0, count)
	for i := 0; i < count; i++ {
		header, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		header = strings.TrimRight(header, "\r\n")
		if len(header) == 0 || header[0] != '$' {
			return nil, fmt.Errorf("expected bulk string, got: %s", header)
		}
		length, err := strconv.Atoi(header[1:])
		if err != nil || length < 0 {
			return nil, fmt.Errorf("invalid bulk string length: %s", header)
		}

		data := make([]byte, length+2)
		n := 0
		for n < len(data) {
			read, err := reader.Read(data[n:])
			if err != nil {
				return nil, err
			}
			n += read
		}
		args = append(args, string(data[:length]))
	}
	return args, nil
}

func readInlineCommand(reader *bufio.Reader) ([]string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return nil, nil
	}
	return strings.Fields(line), nil
}
