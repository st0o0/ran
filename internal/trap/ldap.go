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

type LDAPTrap struct {
	cfg      *config.Config
	logger   *slog.Logger
	metrics  *metrics.Metrics
	limiter  *Limiter
	alerter  alert.Alerter
	listener net.Listener
	wg       sync.WaitGroup
}

func NewLDAP(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) *LDAPTrap {
	return &LDAPTrap{
		cfg:     cfg,
		logger:  logger.With("trap", "ldap"),
		metrics: m,
		limiter: limiter,
		alerter: alerter,
	}
}

func (t *LDAPTrap) Start(ctx context.Context) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", t.cfg.TrapAddr("ldap"))
	if err != nil {
		return fmt.Errorf("ldap listen: %w", err)
	}
	t.listener = ln
	t.logger.Info("listening", "addr", t.cfg.TrapAddr("ldap"))

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
	sess := NewSession("ldap", host, port)

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

	for {
		tag, msgBytes, err := berReadElement(conn)
		if err != nil {
			return
		}
		if tag != 0x30 {
			return
		}

		msgID, rest, err := berReadInteger(msgBytes)
		if err != nil {
			return
		}

		if len(rest) == 0 {
			return
		}
		opTag := rest[0]
		_, opValue, err := berReadTLV(rest)
		if err != nil {
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

	sess.LogAuthAttempt(t.logger,
		slog.String("username", string(name)),
		slog.String("password", password),
	)
	sess.RecordCredentials(t.metrics)
	t.alerter.Alert(ctx, host, "ldap")

	resp := berBuildBindResponse(msgID, 49, "", "Invalid credentials")
	conn.Write(resp)
}

func (t *LDAPTrap) handleSearch(conn net.Conn, msgID int64) {
	resp := berBuildSearchDone(msgID, 50)
	conn.Write(resp)
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

func berEncodeLength(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(length))
	i := 0
	for i < 3 && buf[i] == 0 {
		i++
	}
	numBytes := 4 - i
	result := make([]byte, 1+numBytes)
	result[0] = byte(0x80 | numBytes)
	copy(result[1:], buf[i:])
	return result
}

func berEncodeInteger(tag byte, val int64) []byte {
	var valBytes []byte
	if val == 0 {
		valBytes = []byte{0}
	} else {
		tmp := val
		for tmp > 0 {
			valBytes = append([]byte{byte(tmp & 0xff)}, valBytes...)
			tmp >>= 8
		}
		if valBytes[0]&0x80 != 0 {
			valBytes = append([]byte{0}, valBytes...)
		}
	}
	result := []byte{tag}
	result = append(result, berEncodeLength(len(valBytes))...)
	result = append(result, valBytes...)
	return result
}

func berEncodeOctetString(s string) []byte {
	result := []byte{0x04}
	result = append(result, berEncodeLength(len(s))...)
	result = append(result, []byte(s)...)
	return result
}

func berEncodeSequence(tag byte, children ...[]byte) []byte {
	var payload []byte
	for _, c := range children {
		payload = append(payload, c...)
	}
	result := []byte{tag}
	result = append(result, berEncodeLength(len(payload))...)
	result = append(result, payload...)
	return result
}

func berBuildBindResponse(msgID int64, resultCode int64, matchedDN, diagnostic string) []byte {
	msgIDBytes := berEncodeInteger(0x02, msgID)
	resultCodeBytes := berEncodeInteger(0x0a, resultCode)
	matchedDNBytes := berEncodeOctetString(matchedDN)
	diagnosticBytes := berEncodeOctetString(diagnostic)
	bindResp := berEncodeSequence(0x61, resultCodeBytes, matchedDNBytes, diagnosticBytes)
	return berEncodeSequence(0x30, msgIDBytes, bindResp)
}

func berBuildSearchDone(msgID int64, resultCode int64) []byte {
	msgIDBytes := berEncodeInteger(0x02, msgID)
	resultCodeBytes := berEncodeInteger(0x0a, resultCode)
	matchedDNBytes := berEncodeOctetString("")
	diagnosticBytes := berEncodeOctetString("")
	searchDone := berEncodeSequence(0x65, resultCodeBytes, matchedDNBytes, diagnosticBytes)
	return berEncodeSequence(0x30, msgIDBytes, searchDone)
}
