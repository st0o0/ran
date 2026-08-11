package trap

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

type RDPTrap struct {
	cfg      *config.Config
	logger   *slog.Logger
	metrics  *metrics.Metrics
	limiter  *Limiter
	alerter  alert.Alerter
	listener net.Listener
	wg       sync.WaitGroup
}

func NewRDP(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) *RDPTrap {
	return &RDPTrap{
		cfg:     cfg,
		logger:  logger.With("trap", "rdp"),
		metrics: m,
		limiter: limiter,
		alerter: alerter,
	}
}

func (t *RDPTrap) Start(ctx context.Context) error {
	ln, err := ListenTCP(ctx, t.cfg.TrapAddr("rdp"), t.cfg.ProxyProtocol)
	if err != nil {
		return fmt.Errorf("rdp listen: %w", err)
	}
	t.listener = ln
	t.logger.Info("listening", "addr", t.cfg.TrapAddr("rdp"))

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

func (t *RDPTrap) Stop(_ context.Context) error {
	if t.listener != nil {
		t.listener.Close()
	}
	t.wg.Wait()
	return nil
}

func (t *RDPTrap) handle(ctx context.Context, conn net.Conn) {
	defer t.wg.Done()
	defer conn.Close()

	host, port := ParseAddr(conn.RemoteAddr().String())
	sess := NewSession("rdp", host, port)

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

	// Read TPKT header (4 bytes)
	var tpkt [4]byte
	if _, err := io.ReadFull(conn, tpkt[:]); err != nil {
		return
	}
	if tpkt[0] != 3 || tpkt[1] != 0 {
		return
	}
	tpktLen := int(binary.BigEndian.Uint16(tpkt[2:4]))
	if tpktLen < 11 || tpktLen > 1024 {
		return
	}

	// Read X.224 Connection Request payload
	payload := make([]byte, tpktLen-4)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return
	}

	if len(payload) < 7 {
		return
	}
	crType := payload[1]
	if crType != 0xE0 {
		return
	}

	// Extract username from cookie
	username := ""
	cookieData := payload[6:]
	if idx := bytes.Index(cookieData, []byte("Cookie: mstshash=")); idx >= 0 {
		rest := cookieData[idx+len("Cookie: mstshash="):]
		if end := bytes.Index(rest, []byte("\r\n")); end >= 0 {
			username = strings.TrimSpace(string(rest[:end]))
		}
	}

	sess.LogAuthAttempt(t.logger,
		slog.String("username", username),
	)
	sess.RecordCredentials(t.metrics)
	t.alerter.Alert(ctx, host, "rdp")

	// Send X.224 Connection Confirm with RDP Negotiation Failure
	resp := buildRDPNegFailure()
	_, _ = conn.Write(resp)
}

func buildRDPNegFailure() []byte {
	// TPKT header (4) + X.224 CC (7) + RDP Neg Failure (8) = 19 bytes
	buf := make([]byte, 19)

	// TPKT header
	buf[0] = 3 // version
	buf[1] = 0 // reserved
	binary.BigEndian.PutUint16(buf[2:4], 19)

	// X.224 Connection Confirm
	buf[4] = 14   // length indicator (bytes following, not including itself)
	buf[5] = 0xD0 // type: CC
	// dst-ref (2), src-ref (2), class (1) = all zeros

	// RDP Negotiation Failure
	buf[11] = 0x03 // type
	buf[12] = 0x00 // flags
	binary.BigEndian.PutUint16(buf[13:15], 8) // length
	binary.LittleEndian.PutUint32(buf[15:19], 0x00000002) // SSL_REQUIRED_BY_SERVER

	return buf
}

