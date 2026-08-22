package trap

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

type LDAPTrap struct {
	cfg      *config.Config
	logger   *slog.Logger
	metrics  *metrics.Metrics
	limiter  *Limiter
	alerter  alert.Alerter
	listener *MultiListener
	wg       sync.WaitGroup
}

func NewLDAP(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) *LDAPTrap {
	return &LDAPTrap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
		limiter: limiter,
		alerter: alerter,
	}
}

func (t *LDAPTrap) Start(ctx context.Context) error {
	ln, err := ListenMultiTCP(ctx, t.cfg.TrapAddrs("ldap"), t.cfg.ProxyProtocol)
	if err != nil {
		return fmt.Errorf("ldap listen: %w", err)
	}
	t.listener = ln
	t.logger.Info("listening", "addrs", t.cfg.TrapAddrs("ldap"))

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
			LogErrorStandalone(t.logger, "ldap", "accept_failed", err)
			continue
		}
		t.wg.Add(1)
		go t.handle(ctx, conn)
	}
	return nil
}

func (t *LDAPTrap) Stop(_ context.Context) error {
	if t.listener != nil {
		t.listener.Close()
	}
	t.wg.Wait()
	return nil
}

func (t *LDAPTrap) handle(ctx context.Context, conn net.Conn) {
	defer t.wg.Done()
	defer conn.Close()

	host, port := ParseAddr(conn.RemoteAddr().String())
	_, destPort := ParseAddr(conn.LocalAddr().String())
	sess := NewSession("ldap", "tcp", host, port, destPort, t.logger)

	if !t.limiter.Acquire(host) {
		LogRejected(t.logger, "ldap", "tcp", destPort, host, "rate_limit")
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

	for {
		tag, msgBytes, err := berReadElement(conn)
		if err != nil {
			setOutcomeFromErr(err)
			return
		}
		if tag != 0x30 {
			sess.SetOutcome("error")
			return
		}

		msgID, rest, err := berReadInteger(msgBytes)
		if err != nil {
			sess.SetOutcome("error")
			return
		}

		if len(rest) == 0 {
			sess.SetOutcome("error")
			return
		}
		opTag := rest[0]
		_, opValue, err := berReadTLV(rest)
		if err != nil {
			sess.SetOutcome("error")
			return
		}

		switch opTag & 0x1f {
		case 0: // BindRequest
			t.handleBind(ctx, conn, host, sess, msgID, opValue)
		case 2: // UnbindRequest
			return
		case 3: // SearchRequest
			t.handleSearch(conn, msgID)
		default:
			return
		}
	}
}

func (t *LDAPTrap) handleBind(ctx context.Context, conn net.Conn, host string, sess *Session, msgID int64, data []byte) {
	_, rest, err := berReadInteger(data) // version
	if err != nil {
		return
	}

	name, rest, err := berReadOctetString(rest)
	if err != nil {
		return
	}

	password := ""
	if len(rest) > 0 && rest[0]&0xc0 == 0x80 {
		_, pwBytes, err := berReadTLV(rest)
		if err == nil {
			password = string(pwBytes)
		}
	}

	sess.LogAuthAttempt(
		slog.String("username", string(name)),
		slog.String("password", password),
	)
	sess.RecordCredentials(t.metrics)
	t.alerter.Alert(ctx, host, "ldap", map[string]string{"username": string(name), "password": password})

	resp := berBuildBindResponse(msgID, 49, "", "Invalid credentials")
	_, _ = conn.Write(resp)
}

func (t *LDAPTrap) handleSearch(conn net.Conn, msgID int64) {
	resp := berBuildSearchDone(msgID, 50)
	_, _ = conn.Write(resp)
}

// BER encoding helpers

func berReadElement(r io.Reader) (tag byte, value []byte, err error) {
	var tagBuf [1]byte
	if _, err = io.ReadFull(r, tagBuf[:]); err != nil {
		return
	}
	tag = tagBuf[0]

	length, err := berReadLength(r)
	if err != nil {
		return
	}

	value = make([]byte, length)
	_, err = io.ReadFull(r, value)
	return
}

func berReadLength(r io.Reader) (int, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	if b[0] < 0x80 {
		return int(b[0]), nil
	}
	numBytes := int(b[0] & 0x7f)
	if numBytes == 0 || numBytes > 4 {
		return 0, fmt.Errorf("ber: unsupported length encoding")
	}
	buf := make([]byte, numBytes)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, err
	}
	length := 0
	for _, v := range buf {
		length = (length << 8) | int(v)
	}
	return length, nil
}

func berReadTLV(data []byte) (tag byte, value []byte, err error) {
	if len(data) < 2 {
		return 0, nil, fmt.Errorf("ber: short data")
	}
	tag = data[0]
	offset := 1
	if data[offset] < 0x80 {
		length := int(data[offset])
		offset++
		if offset+length > len(data) {
			return 0, nil, fmt.Errorf("ber: truncated")
		}
		value = data[offset : offset+length]
		return
	}
	numBytes := int(data[offset] & 0x7f)
	offset++
	if offset+numBytes > len(data) {
		return 0, nil, fmt.Errorf("ber: truncated length")
	}
	length := 0
	for i := 0; i < numBytes; i++ {
		length = (length << 8) | int(data[offset+i])
	}
	offset += numBytes
	if offset+length > len(data) {
		return 0, nil, fmt.Errorf("ber: truncated value")
	}
	value = data[offset : offset+length]
	return
}

func berReadInteger(data []byte) (int64, []byte, error) {
	if len(data) < 2 || data[0] != 0x02 {
		return 0, nil, fmt.Errorf("ber: expected INTEGER")
	}
	length := int(data[1])
	if 2+length > len(data) {
		return 0, nil, fmt.Errorf("ber: truncated integer")
	}
	var val int64
	for _, b := range data[2 : 2+length] {
		val = (val << 8) | int64(b)
	}
	return val, data[2+length:], nil
}

func berReadOctetString(data []byte) ([]byte, []byte, error) {
	if len(data) < 2 || data[0] != 0x04 {
		return nil, nil, fmt.Errorf("ber: expected OCTET STRING")
	}
	length := int(data[1])
	if 2+length > len(data) {
		return nil, nil, fmt.Errorf("ber: truncated octet string")
	}
	return data[2 : 2+length], data[2+length:], nil
}

func berBuildBindResponse(msgID int64, resultCode int64, matchedDN, diagnostic string) []byte {
	msgIDBytes := berInteger(0x02, msgID)
	resultCodeBytes := berInteger(0x0a, resultCode)
	matchedDNBytes := berOctetString(0x04, []byte(matchedDN))
	diagnosticBytes := berOctetString(0x04, []byte(diagnostic))
	bindResp := berSequence(0x61, resultCodeBytes, matchedDNBytes, diagnosticBytes)
	return berSequence(0x30, msgIDBytes, bindResp)
}

func berBuildSearchDone(msgID int64, resultCode int64) []byte {
	msgIDBytes := berInteger(0x02, msgID)
	resultCodeBytes := berInteger(0x0a, resultCode)
	matchedDNBytes := berOctetString(0x04, []byte(""))
	diagnosticBytes := berOctetString(0x04, []byte(""))
	searchDone := berSequence(0x65, resultCodeBytes, matchedDNBytes, diagnosticBytes)
	return berSequence(0x30, msgIDBytes, searchDone)
}
