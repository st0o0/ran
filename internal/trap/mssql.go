package trap

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"unicode/utf16"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

type MSSQLTrap struct {
	cfg      *config.Config
	logger   *slog.Logger
	metrics  *metrics.Metrics
	limiter  *Limiter
	alerter  alert.Alerter
	listener *MultiListener
	wg       sync.WaitGroup
}

func NewMSSQL(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) *MSSQLTrap {
	return &MSSQLTrap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
		limiter: limiter,
		alerter: alerter,
	}
}

func (t *MSSQLTrap) Start(ctx context.Context) error {
	ln, err := ListenMultiTCP(ctx, t.cfg.TrapAddrs("mssql"), t.cfg.ProxyProtocol)
	if err != nil {
		return fmt.Errorf("mssql listen: %w", err)
	}
	t.listener = ln
	t.logger.Info("listening", "addrs", t.cfg.TrapAddrs("mssql"))

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
			LogErrorStandalone(t.logger, "mssql", "accept_failed", err)
			continue
		}
		t.wg.Add(1)
		go t.handle(ctx, conn)
	}
	return nil
}

func (t *MSSQLTrap) Stop(_ context.Context) error {
	if t.listener != nil {
		t.listener.Close()
	}
	t.wg.Wait()
	return nil
}

func (t *MSSQLTrap) handle(ctx context.Context, conn net.Conn) {
	defer t.wg.Done()
	defer conn.Close()

	host, port := ParseAddr(conn.RemoteAddr().String())
	_, destPort := ParseAddr(conn.LocalAddr().String())
	sess := NewSession("mssql", "tcp", host, port, destPort, t.logger)

	if !t.limiter.Acquire(host) {
		LogRejected(t.logger, "mssql", "tcp", destPort, host, "rate_limit")
		return
	}
	defer t.limiter.Release(host)

	sess.LogConnect()
	sess.RecordStart(t.metrics)
	defer sess.RecordEnd(t.metrics)
	defer sess.LogDisconnect()

	_ = conn.SetDeadline(deadlineFromContext(ctx, t.cfg.ResolveSessionTimeout("mssql")))

	setOutcomeFromErr := func(err error) {
		if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() {
			sess.SetOutcome("timeout")
		} else {
			sess.SetOutcome("error")
		}
	}

	header := make([]byte, 8)
	if _, err := io.ReadFull(conn, header); err != nil {
		setOutcomeFromErr(err)
		return
	}
	if header[0] != 0x12 {
		sess.SetOutcome("probe")
		return
	}
	pktLen := int(binary.BigEndian.Uint16(header[2:4]))
	if pktLen < 8 || pktLen > 1<<20 {
		sess.SetOutcome("probe")
		return
	}
	payload := make([]byte, pktLen-8)
	if _, err := io.ReadFull(conn, payload); err != nil {
		setOutcomeFromErr(err)
		return
	}

	preloginResp := buildTDSPreloginResponse()
	if _, err := conn.Write(preloginResp); err != nil {
		setOutcomeFromErr(err)
		return
	}

	maxRetries := t.cfg.ResolveMaxAuthRetries("mssql")
	authDelay := t.cfg.ResolveAuthDelay("mssql")

	for attempt := 0; maxRetries == 0 || attempt < maxRetries; attempt++ {
		if _, err := io.ReadFull(conn, header); err != nil {
			if sess.authAttempts > 0 {
				return
			}
			setOutcomeFromErr(err)
			return
		}
		if header[0] != 0x10 {
			if sess.authAttempts == 0 {
				sess.SetOutcome("probe")
			}
			return
		}
		loginLen := int(binary.BigEndian.Uint16(header[2:4]))
		if loginLen < 8 || loginLen > 1<<20 {
			if sess.authAttempts == 0 {
				sess.SetOutcome("probe")
			}
			return
		}
		body := make([]byte, loginLen-8)
		if _, err := io.ReadFull(conn, body); err != nil {
			if sess.authAttempts > 0 {
				return
			}
			setOutcomeFromErr(err)
			return
		}

		username, password := parseTDSLogin7(body)
		sess.LogAuthAttempt(
			slog.String("username", username),
			slog.String("password", password),
		)
		sess.RecordCredentials(t.metrics)
		t.alerter.Alert(ctx, host, "mssql", map[string]string{"username": username, "password": password})

		if authDelay > 0 {
			if err := authSleep(ctx, authDelay, attempt); err != nil {
				sess.SetOutcome("timeout")
				return
			}
		}

		_, _ = conn.Write(buildTDSErrorResponse())
	}
}

func buildTDSPreloginResponse() []byte {
	// Option list: VERSION (5 bytes) + ENCRYPTION (5 bytes) + TERMINATOR (1 byte) = 11 bytes
	// VERSION data starts at offset 11, length 6
	// ENCRYPTION data starts at offset 17, length 1
	var payload []byte

	// VERSION option
	payload = append(payload, 0x00)
	payload = append(payload, 0x00, 0x0B) // offset 11
	payload = append(payload, 0x00, 0x06) // length 6

	// ENCRYPTION option
	payload = append(payload, 0x01)
	payload = append(payload, 0x00, 0x11) // offset 17
	payload = append(payload, 0x00, 0x01) // length 1

	// TERMINATOR
	payload = append(payload, 0xFF)

	// VERSION data: 15.0.2000.0
	payload = append(payload, 0x0F, 0x00, 0x07, 0xD0, 0x00, 0x00)

	// ENCRYPTION data: NOT_SUP
	payload = append(payload, 0x02)

	return buildTDSPacket(0x12, 0x01, payload)
}

func parseTDSLogin7(body []byte) (username, password string) {
	if len(body) < 64 {
		return "", ""
	}

	usernameOffset := int(binary.LittleEndian.Uint16(body[56:58]))
	usernameLength := int(binary.LittleEndian.Uint16(body[58:60]))
	passwordOffset := int(binary.LittleEndian.Uint16(body[60:62]))
	passwordLength := int(binary.LittleEndian.Uint16(body[62:64]))

	if usernameOffset+usernameLength*2 > len(body) {
		return "", ""
	}
	username = utf16LEToString(body[usernameOffset : usernameOffset+usernameLength*2])

	if passwordOffset+passwordLength*2 > len(body) {
		return username, ""
	}
	password = decodeTDSPassword(body[passwordOffset : passwordOffset+passwordLength*2])

	return username, password
}

func decodeTDSPassword(data []byte) string {
	decoded := make([]byte, len(data))
	for i, b := range data {
		b ^= 0xA5
		b = (b << 4) | (b >> 4)
		decoded[i] = b
	}
	return utf16LEToString(decoded)
}

func utf16LEToString(data []byte) string {
	if len(data)%2 != 0 {
		data = data[:len(data)-1]
	}
	u16 := make([]uint16, len(data)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	return string(utf16.Decode(u16))
}

func stringToUTF16LE(s string) []byte {
	runes := utf16.Encode([]rune(s))
	b := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return b
}

func buildTDSPacket(pktType byte, status byte, payload []byte) []byte {
	pkt := make([]byte, 8+len(payload))
	pkt[0] = pktType
	pkt[1] = status
	binary.BigEndian.PutUint16(pkt[2:4], uint16(8+len(payload)))
	pkt[4] = 0 // SPID
	pkt[5] = 0
	pkt[6] = 0 // Packet
	pkt[7] = 0 // Window
	copy(pkt[8:], payload)
	return pkt
}

func buildTDSErrorResponse() []byte {
	msg := stringToUTF16LE("Login failed")
	msgChars := len(msg) / 2

	var token []byte
	token = binary.LittleEndian.AppendUint32(token, 18456)          // error number
	token = append(token, 1)                                        // state
	token = append(token, 14)                                       // class/severity
	token = binary.LittleEndian.AppendUint16(token, uint16(msgChars)) // message length
	token = append(token, msg...)
	token = append(token, 0) // server name length
	token = append(token, 0) // proc name length
	token = binary.LittleEndian.AppendUint32(token, 0)              // line number

	var payload []byte
	payload = append(payload, 0xAA)                                      // ERROR token
	payload = binary.LittleEndian.AppendUint16(payload, uint16(len(token))) // token data length
	payload = append(payload, token...)

	return buildTDSPacket(0x04, 0x01, payload)
}
