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

type SOCKS5Trap struct {
	cfg      *config.Config
	logger   *slog.Logger
	metrics  *metrics.Metrics
	limiter  *Limiter
	alerter  alert.Alerter
	listener net.Listener
	wg       sync.WaitGroup
}

func NewSOCKS5(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) *SOCKS5Trap {
	return &SOCKS5Trap{
		cfg:     cfg,
		logger:  logger.With("trap", "socks5"),
		metrics: m,
		limiter: limiter,
		alerter: alerter,
	}
}

func (t *SOCKS5Trap) Start(ctx context.Context) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", t.cfg.TrapAddr("socks5"))
	if err != nil {
		return fmt.Errorf("socks5 listen: %w", err)
	}
	t.listener = ln
	t.logger.Info("listening", "addr", t.cfg.TrapAddr("socks5"))

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

func (t *SOCKS5Trap) Stop(_ context.Context) error {
	if t.listener != nil {
		t.listener.Close()
	}
	t.wg.Wait()
	return nil
}

func (t *SOCKS5Trap) handle(ctx context.Context, conn net.Conn) {
	defer t.wg.Done()
	defer conn.Close()

	host, port := ParseAddr(conn.RemoteAddr().String())
	sess := NewSession("socks5", host, port)

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

	// Read greeting
	var ver [1]byte
	if _, err := io.ReadFull(conn, ver[:]); err != nil {
		return
	}
	if ver[0] != 0x05 {
		return
	}

	var nmethods [1]byte
	if _, err := io.ReadFull(conn, nmethods[:]); err != nil {
		return
	}

	methods := make([]byte, nmethods[0])
	if _, err := io.ReadFull(conn, methods); err != nil {
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
		return
	}

	var ulen [1]byte
	if _, err := io.ReadFull(conn, ulen[:]); err != nil {
		return
	}
	username := make([]byte, ulen[0])
	if _, err := io.ReadFull(conn, username); err != nil {
		return
	}

	var plen [1]byte
	if _, err := io.ReadFull(conn, plen[:]); err != nil {
		return
	}
	password := make([]byte, plen[0])
	if _, err := io.ReadFull(conn, password); err != nil {
		return
	}

	sess.LogAuthAttempt(t.logger,
		slog.String("username", string(username)),
		slog.String("password", string(password)),
	)
	sess.RecordCredentials(t.metrics)
	t.alerter.Alert(ctx, host, "socks5")

	// Auth failure
	_, _ = conn.Write([]byte{0x01, 0x01})
}

func (t *SOCKS5Trap) handleNoAuth(ctx context.Context, conn net.Conn, host string, sess *Session) {
	// Read connect request
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
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
			return
		}
		targetAddr = net.IP(ip[:]).String()
	case 0x03: // Domain
		var dlen [1]byte
		if _, err := io.ReadFull(conn, dlen[:]); err != nil {
			return
		}
		domain := make([]byte, dlen[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return
		}
		targetAddr = string(domain)
	case 0x04: // IPv6
		var ip [16]byte
		if _, err := io.ReadFull(conn, ip[:]); err != nil {
			return
		}
		targetAddr = net.IP(ip[:]).String()
	default:
		return
	}

	var portBytes [2]byte
	if _, err := io.ReadFull(conn, portBytes[:]); err != nil {
		return
	}
	targetPort := binary.BigEndian.Uint16(portBytes[:])

	target := fmt.Sprintf("%s:%d", targetAddr, targetPort)
	sess.LogPayload(t.logger, "connect_request", slog.String("target", target))
	t.alerter.Alert(ctx, host, "socks5")

	// General failure reply
	resp := []byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	_, _ = conn.Write(resp)
}
