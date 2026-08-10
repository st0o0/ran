package trap

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

type PostgresTrap struct {
	cfg      *config.Config
	logger   *slog.Logger
	metrics  *metrics.Metrics
	limiter  *Limiter
	alerter  alert.Alerter
	listener net.Listener
	wg       sync.WaitGroup
}

func NewPostgres(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) *PostgresTrap {
	return &PostgresTrap{
		cfg:     cfg,
		logger:  logger.With("trap", "postgres"),
		metrics: m,
		limiter: limiter,
		alerter: alerter,
	}
}

func (t *PostgresTrap) Start(ctx context.Context) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", t.cfg.TrapAddr("postgres"))
	if err != nil {
		return fmt.Errorf("postgres listen: %w", err)
	}
	t.listener = ln
	t.logger.Info("listening", "addr", t.cfg.TrapAddr("postgres"))

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

func (t *PostgresTrap) Stop(_ context.Context) error {
	if t.listener != nil {
		t.listener.Close()
	}
	t.wg.Wait()
	return nil
}

func (t *PostgresTrap) handle(ctx context.Context, conn net.Conn) {
	defer t.wg.Done()
	defer conn.Close()

	host, port := ParseAddr(conn.RemoteAddr().String())
	sess := NewSession("postgres", host, port)

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

	startup, err := readPgStartupMessage(conn)
	if err != nil {
		return
	}

	if len(startup) == 4 && binary.BigEndian.Uint32(startup) == 80877103 {
		conn.Write([]byte{'N'})
		startup, err = readPgStartupMessage(conn)
		if err != nil {
			return
		}
	}

	username := parsePgStartupParams(startup)

	var auth [9]byte
	auth[0] = 'R'
	binary.BigEndian.PutUint32(auth[1:5], 8)
	binary.BigEndian.PutUint32(auth[5:9], 3)
	if _, err := conn.Write(auth[:]); err != nil {
		return
	}

	password, err := readPgPasswordMessage(conn)
	if err != nil {
		return
	}

	sess.LogAuthAttempt(t.logger,
		slog.String("username", username),
		slog.String("password", password),
	)
	sess.RecordCredentials(t.metrics)
	t.alerter.Alert(ctx, host, "postgres")

	errMsg := fmt.Sprintf("password authentication failed for user \"%s\"", username)
	writePgErrorResponse(conn, errMsg)
}

func readPgStartupMessage(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint32(lenBuf[:]))
	if length < 4 || length > 1<<20 {
		return nil, fmt.Errorf("invalid startup length: %d", length)
	}
	payload := make([]byte, length-4)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func parsePgStartupParams(data []byte) string {
	if len(data) < 4 {
		return ""
	}
	params := data[4:]
	for len(params) > 1 {
		keyEnd := 0
		for keyEnd < len(params) && params[keyEnd] != 0 {
			keyEnd++
		}
		if keyEnd >= len(params) {
			break
		}
		key := string(params[:keyEnd])
		params = params[keyEnd+1:]

		valEnd := 0
		for valEnd < len(params) && params[valEnd] != 0 {
			valEnd++
		}
		if valEnd >= len(params) {
			break
		}
		val := string(params[:valEnd])
		params = params[valEnd+1:]

		if key == "user" {
			return val
		}
	}
	return ""
}

func readPgPasswordMessage(r io.Reader) (string, error) {
	var tag [1]byte
	if _, err := io.ReadFull(r, tag[:]); err != nil {
		return "", err
	}
	if tag[0] != 'p' {
		return "", fmt.Errorf("expected password message, got %c", tag[0])
	}
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return "", err
	}
	length := int(binary.BigEndian.Uint32(lenBuf[:]))
	if length < 4 || length > 1<<20 {
		return "", fmt.Errorf("invalid password length: %d", length)
	}
	data := make([]byte, length-4)
	if _, err := io.ReadFull(r, data); err != nil {
		return "", err
	}
	if len(data) > 0 && data[len(data)-1] == 0 {
		data = data[:len(data)-1]
	}
	return string(data), nil
}

func writePgErrorResponse(w io.Writer, msg string) {
	var body []byte
	body = append(body, 'S')
	body = append(body, "FATAL\x00"...)
	body = append(body, 'M')
	body = append(body, msg...)
	body = append(body, 0)
	body = append(body, 0)

	var pkt []byte
	pkt = append(pkt, 'E')
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)+4))
	pkt = append(pkt, lenBuf[:]...)
	pkt = append(pkt, body...)
	w.Write(pkt)
}
