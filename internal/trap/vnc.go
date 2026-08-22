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
	listener *MultiListener
	wg       sync.WaitGroup
}

func NewVNC(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) *VNCTrap {
	return &VNCTrap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
		limiter: limiter,
		alerter: alerter,
	}
}

func (t *VNCTrap) Start(ctx context.Context) error {
	ln, err := ListenMultiTCP(ctx, t.cfg.TrapAddrs("vnc"), t.cfg.ProxyProtocol)
	if err != nil {
		return fmt.Errorf("vnc listen: %w", err)
	}
	t.listener = ln
	t.logger.Info("listening", "addrs", t.cfg.TrapAddrs("vnc"))

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
			LogErrorStandalone(t.logger, "vnc", "accept_failed", err)
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
	_, destPort := ParseAddr(conn.LocalAddr().String())
	sess := NewSession("vnc", "tcp", host, port, destPort, t.logger)

	if !t.limiter.Acquire(host) {
		LogRejected(t.logger, "vnc", "tcp", destPort, host, "rate_limit")
		return
	}
	defer t.limiter.Release(host)

	sess.LogConnect()
	sess.RecordStart(t.metrics)
	defer sess.RecordEnd(t.metrics)
	defer sess.LogDisconnect()

	_ = conn.SetDeadline(deadlineFromContext(ctx, t.cfg.SessionTimeout))

	setOutcomeFromErr := func(err error) {
		if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() {
			sess.SetOutcome("timeout")
		} else {
			sess.SetOutcome("error")
		}
	}

	// Send server RFB version
	if _, err := conn.Write([]byte("RFB 003.008\n")); err != nil {
		setOutcomeFromErr(err)
		return
	}

	// Read client RFB version
	var clientVersion [12]byte
	if _, err := io.ReadFull(conn, clientVersion[:]); err != nil {
		setOutcomeFromErr(err)
		return
	}

	// Send security types: 1 type available, type 2 (VNC Authentication)
	if _, err := conn.Write([]byte{1, 2}); err != nil {
		setOutcomeFromErr(err)
		return
	}

	// Read client security type selection (1 byte)
	var secType [1]byte
	if _, err := io.ReadFull(conn, secType[:]); err != nil {
		setOutcomeFromErr(err)
		return
	}

	// Send 16-byte random challenge
	var challenge [16]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		setOutcomeFromErr(err)
		return
	}
	if _, err := conn.Write(challenge[:]); err != nil {
		setOutcomeFromErr(err)
		return
	}

	// Read 16-byte DES-encrypted response
	var response [16]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		setOutcomeFromErr(err)
		return
	}

	sess.LogAuthAttempt(
		slog.String("challenge", hex.EncodeToString(challenge[:])),
		slog.String("response", hex.EncodeToString(response[:])),
	)
	sess.RecordCredentials(t.metrics)
	t.alerter.Alert(ctx, host, "vnc", nil)

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
