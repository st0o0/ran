package trap

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"io"
	"log/slog"
	"net"

	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

type VNCTrap struct {
	*tcpServer
	cfg     *config.Config
	logger  *slog.Logger
	metrics *metrics.Metrics
}

func NewVNC(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter Reporter) *VNCTrap {
	t := &VNCTrap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
	}
	t.tcpServer = newTCPServer("vnc", cfg, logger, m, limiter, alerter, t.handle)
	return t
}

func (t *VNCTrap) handle(ctx context.Context, conn net.Conn, sess *Session) {
	// Send server RFB version
	if _, err := conn.Write([]byte("RFB 003.008\n")); err != nil {
		setOutcome(sess, err)
		return
	}

	// Read client RFB version
	var clientVersion [12]byte
	if _, err := io.ReadFull(conn, clientVersion[:]); err != nil {
		setOutcome(sess, err)
		return
	}

	// Send security types: 1 type available, type 2 (VNC Authentication)
	if _, err := conn.Write([]byte{1, 2}); err != nil {
		setOutcome(sess, err)
		return
	}

	// Read client security type selection (1 byte)
	var secType [1]byte
	if _, err := io.ReadFull(conn, secType[:]); err != nil {
		setOutcome(sess, err)
		return
	}

	// Send 16-byte random challenge
	var challenge [16]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		setOutcome(sess, err)
		return
	}
	if _, err := conn.Write(challenge[:]); err != nil {
		setOutcome(sess, err)
		return
	}

	// Read 16-byte DES-encrypted response
	var response [16]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		setOutcome(sess, err)
		return
	}

	sess.LogAuthAttempt(
		slog.String("challenge", hex.EncodeToString(challenge[:])),
		slog.String("response", hex.EncodeToString(response[:])),
	)
	sess.RecordCredentials(t.metrics)
	sess.Alert(ctx, map[string]string{"kind": "auth_response"})

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
