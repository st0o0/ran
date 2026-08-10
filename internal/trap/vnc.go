package trap

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

type VNCTrap struct {
	cfg      *config.Config
	logger   *slog.Logger
	metrics  *metrics.Metrics
	limiter  *Limiter
	alerter  alert.Alerter
	listener net.Listener
	wg       sync.WaitGroup
}

func NewVNC(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) *VNCTrap {
	return &VNCTrap{
		cfg:     cfg,
		logger:  logger.With("trap", "vnc"),
		metrics: m,
		limiter: limiter,
		alerter: alerter,
	}
}

func (t *VNCTrap) Start(ctx context.Context) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", t.cfg.TrapAddr("vnc"))
	if err != nil {
		return fmt.Errorf("vnc listen: %w", err)
	}
	t.listener = ln
	t.logger.Info("listening", "addr", t.cfg.TrapAddr("vnc"))

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

func (t *VNCTrap) Stop(_ context.Context) error {
	if t.listener != nil {
		t.listener.Close()
	}
	t.wg.Wait()
	return nil
}

func (t *VNCTrap) handle(ctx context.Context, conn net.Conn) {
	defer t.wg.Done()
	defer conn.Close()

	host, port := ParseAddr(conn.RemoteAddr().String())
	sess := NewSession("vnc", host, port)

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

	// Send server RFB version
	if _, err := conn.Write([]byte("RFB 003.008\n")); err != nil {
		return
	}

	// Read client RFB version
	var clientVersion [12]byte
	if _, err := io.ReadFull(conn, clientVersion[:]); err != nil {
		return
	}

	// Send security types: 1 type available, type 2 (VNC Authentication)
	if _, err := conn.Write([]byte{1, 2}); err != nil {
		return
	}

	// Read client security type selection (1 byte)
	var secType [1]byte
	if _, err := io.ReadFull(conn, secType[:]); err != nil {
		return
	}

	// Send 16-byte random challenge
	var challenge [16]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return
	}
	if _, err := conn.Write(challenge[:]); err != nil {
		return
	}

	// Read 16-byte DES-encrypted response
	var response [16]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		return
	}

	sess.LogAuthAttempt(t.logger,
		slog.String("challenge", hex.EncodeToString(challenge[:])),
		slog.String("response", hex.EncodeToString(response[:])),
	)
	sess.RecordCredentials(t.metrics)
	t.alerter.Alert(ctx, host, "vnc")

	// Send SecurityResult: failed (1)
	var result [4]byte
	binary.BigEndian.PutUint32(result[:], 1)
	_, _ = conn.Write(result[:])

	// Send reason string (uint32 length + null-terminated string)
	reason := "Authentication failed"
	var reasonLen [4]byte
	binary.BigEndian.PutUint32(reasonLen[:], uint32(len(reason)))
	_, _ = conn.Write(reasonLen[:])
	_, _ = conn.Write([]byte(reason))
}
