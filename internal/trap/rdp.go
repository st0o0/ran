package trap

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"strings"

	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

type RDPTrap struct {
	*tcpServer
	cfg     *config.Config
	logger  *slog.Logger
	metrics *metrics.Metrics
}

func NewRDP(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter Reporter) *RDPTrap {
	t := &RDPTrap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
	}
	t.tcpServer = newTCPServer("rdp", cfg, logger, m, limiter, alerter, t.handle)
	return t
}

func (t *RDPTrap) handle(ctx context.Context, conn net.Conn, sess *Session) {
	// One attempt per TCP session by design: the X.224 connection request carries
	// the only user name, and the negotiation failure that answers it ends the
	// exchange (a real server closes here too). RAN_MAX_AUTH_RETRIES and
	// RAN_AUTH_DELAY therefore do not apply.
	// Read TPKT header (4 bytes)
	var tpkt [4]byte
	if _, err := io.ReadFull(conn, tpkt[:]); err != nil {
		setOutcome(sess, err)
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
		setOutcome(sess, err)
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

	sess.LogAuthAttempt(
		slog.String("username", username),
	)
	sess.RecordCredentials(t.metrics)
	sess.Alert(ctx, map[string]string{"username": username})

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
	buf[11] = 0x03                                        // type
	buf[12] = 0x00                                        // flags
	binary.BigEndian.PutUint16(buf[13:15], 8)             // length
	binary.LittleEndian.PutUint32(buf[15:19], 0x00000002) // SSL_REQUIRED_BY_SERVER

	return buf
}
