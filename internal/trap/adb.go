package trap

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

const (
	adbCmdCNXN = 0x4e584e43
	adbCmdAUTH = 0x48545541
	adbHdrSize = 24
)

type ADBTrap struct {
	cfg      *config.Config
	logger   *slog.Logger
	metrics  *metrics.Metrics
	limiter  *Limiter
	alerter  alert.Alerter
	listener *MultiListener
	wg       sync.WaitGroup
}

func NewADB(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) *ADBTrap {
	return &ADBTrap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
		limiter: limiter,
		alerter: alerter,
	}
}

func (t *ADBTrap) Start(ctx context.Context) error {
	ln, err := ListenMultiTCP(ctx, t.cfg.TrapAddrs("adb"), t.cfg.ProxyProtocol)
	if err != nil {
		return fmt.Errorf("adb listen: %w", err)
	}
	t.listener = ln
	t.logger.Info("listening", "addrs", t.cfg.TrapAddrs("adb"))

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

func (t *ADBTrap) Stop(_ context.Context) error {
	if t.listener != nil {
		t.listener.Close()
	}
	t.wg.Wait()
	return nil
}

func (t *ADBTrap) handle(ctx context.Context, conn net.Conn) {
	defer t.wg.Done()
	defer conn.Close()

	host, port := ParseAddr(conn.RemoteAddr().String())
	_, destPort := ParseAddr(conn.LocalAddr().String())
	sess := NewSession("adb", host, port, destPort, t.logger)

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

	hdr := make([]byte, adbHdrSize)
	if _, err := readFull(conn, hdr); err != nil {
		return
	}

	cmd := binary.LittleEndian.Uint32(hdr[0:4])
	if cmd != adbCmdCNXN {
		sess.LogPayload("adb_unknown", slog.String("raw", fmt.Sprintf("%x", hdr)))
		return
	}

	dataLen := binary.LittleEndian.Uint32(hdr[12:16])
	if dataLen > 4096 {
		dataLen = 4096
	}

	var identity string
	if dataLen > 0 {
		payload := make([]byte, dataLen)
		if _, err := readFull(conn, payload); err == nil {
			identity = string(payload)
		}
	}

	sess.LogPayload("adb_identity", slog.String("identity", identity))
	t.alerter.Alert(ctx, host, "adb", map[string]string{"identity": identity})

	token := make([]byte, 20)
	_, _ = rand.Read(token)

	resp := make([]byte, adbHdrSize+len(token))
	binary.LittleEndian.PutUint32(resp[0:4], adbCmdAUTH)
	binary.LittleEndian.PutUint32(resp[4:8], 1) // AUTH_TOKEN
	binary.LittleEndian.PutUint32(resp[8:12], 0)
	binary.LittleEndian.PutUint32(resp[12:16], uint32(len(token)))
	copy(resp[adbHdrSize:], token)

	_, _ = conn.Write(resp)
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
