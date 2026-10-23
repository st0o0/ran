package trap

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

type SOCKS5Trap struct {
	*tcpServer
	cfg     *config.Config
	logger  *slog.Logger
	metrics *metrics.Metrics
}

func NewSOCKS5(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter Reporter) *SOCKS5Trap {
	t := &SOCKS5Trap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
	}
	t.tcpServer = newTCPServer("socks5", cfg, logger, m, limiter, alerter, t.handle)
	return t
}

func (t *SOCKS5Trap) handle(ctx context.Context, conn net.Conn, sess *Session) {
	host := sess.SourceIP
	// Read greeting
	var ver [1]byte
	if _, err := io.ReadFull(conn, ver[:]); err != nil {
		setOutcome(sess, err)
		return
	}
	if ver[0] != 0x05 {
		sess.SetOutcome("error")
		return
	}

	var nmethods [1]byte
	if _, err := io.ReadFull(conn, nmethods[:]); err != nil {
		setOutcome(sess, err)
		return
	}

	methods := make([]byte, nmethods[0])
	if _, err := io.ReadFull(conn, methods); err != nil {
		setOutcome(sess, err)
		return
	}

	hasUserPass := false
	hasNoAuth := false
	for _, m := range methods {
		if m == 0x02 {
			hasUserPass = true
		}
		if m == 0x00 {
			hasNoAuth = true
		}
	}

	if hasUserPass {
		// Select username/password auth
		_, _ = conn.Write([]byte{0x05, 0x02})
		t.handleUserPassAuth(ctx, conn, host, sess)
	} else if hasNoAuth {
		// Select no auth
		_, _ = conn.Write([]byte{0x05, 0x00})
		t.handleNoAuth(ctx, conn, host, sess)
	} else {
		// No acceptable methods
		_, _ = conn.Write([]byte{0x05, 0xFF})
	}
}

func (t *SOCKS5Trap) handleUserPassAuth(ctx context.Context, conn net.Conn, host string, sess *Session) {
	var authVer [1]byte
	if _, err := io.ReadFull(conn, authVer[:]); err != nil {
		setOutcome(sess, err)
		return
	}

	var ulen [1]byte
	if _, err := io.ReadFull(conn, ulen[:]); err != nil {
		setOutcome(sess, err)
		return
	}
	username := make([]byte, ulen[0])
	if _, err := io.ReadFull(conn, username); err != nil {
		setOutcome(sess, err)
		return
	}

	var plen [1]byte
	if _, err := io.ReadFull(conn, plen[:]); err != nil {
		setOutcome(sess, err)
		return
	}
	password := make([]byte, plen[0])
	if _, err := io.ReadFull(conn, password); err != nil {
		setOutcome(sess, err)
		return
	}

	sess.LogAuthAttempt(
		slog.String("username", string(username)),
		slog.String("password", string(password)),
	)
	sess.RecordCredentials(t.metrics)
	sess.Alert(ctx, map[string]string{"username": string(username), "password": string(password)})

	// Auth failure
	_, _ = conn.Write([]byte{0x01, 0x01})
}

func (t *SOCKS5Trap) handleNoAuth(ctx context.Context, conn net.Conn, host string, sess *Session) {
	// Read connect request
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		setOutcome(sess, err)
		return
	}
	if hdr[0] != 0x05 {
		return
	}

	var targetAddr string
	switch hdr[3] { // ATYP
	case 0x01: // IPv4
		var ip [4]byte
		if _, err := io.ReadFull(conn, ip[:]); err != nil {
			setOutcome(sess, err)
			return
		}
		targetAddr = net.IP(ip[:]).String()
	case 0x03: // Domain
		var dlen [1]byte
		if _, err := io.ReadFull(conn, dlen[:]); err != nil {
			setOutcome(sess, err)
			return
		}
		domain := make([]byte, dlen[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			setOutcome(sess, err)
			return
		}
		targetAddr = string(domain)
	case 0x04: // IPv6
		var ip [16]byte
		if _, err := io.ReadFull(conn, ip[:]); err != nil {
			setOutcome(sess, err)
			return
		}
		targetAddr = net.IP(ip[:]).String()
	default:
		return
	}

	var portBytes [2]byte
	if _, err := io.ReadFull(conn, portBytes[:]); err != nil {
		setOutcome(sess, err)
		return
	}
	targetPort := binary.BigEndian.Uint16(portBytes[:])

	target := fmt.Sprintf("%s:%d", targetAddr, targetPort)
	sess.LogPayload("connect_request", slog.String("target", target))
	sess.Alert(ctx, map[string]string{"target": target})

	// General failure reply
	resp := []byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	_, _ = conn.Write(resp)
}
