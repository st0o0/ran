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

type SMBTrap struct {
	cfg      *config.Config
	logger   *slog.Logger
	metrics  *metrics.Metrics
	limiter  *Limiter
	alerter  alert.Alerter
	listener *MultiListener
	wg       sync.WaitGroup
}

func NewSMB(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) *SMBTrap {
	return &SMBTrap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
		limiter: limiter,
		alerter: alerter,
	}
}

func (t *SMBTrap) Start(ctx context.Context) error {
	ln, err := ListenMultiTCP(ctx, t.cfg.TrapAddrs("smb"), t.cfg.ProxyProtocol)
	if err != nil {
		return fmt.Errorf("smb listen: %w", err)
	}
	t.listener = ln
	t.logger.Info("listening", "addrs", t.cfg.TrapAddrs("smb"))

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
			LogErrorStandalone(t.logger, "smb", "accept_failed", err)
			continue
		}
		t.wg.Add(1)
		go t.handle(ctx, conn)
	}
	return nil
}

func (t *SMBTrap) Stop(_ context.Context) error {
	if t.listener != nil {
		t.listener.Close()
	}
	t.wg.Wait()
	return nil
}

func (t *SMBTrap) handle(ctx context.Context, conn net.Conn) {
	defer t.wg.Done()
	defer conn.Close()

	host, port := ParseAddr(conn.RemoteAddr().String())
	_, destPort := ParseAddr(conn.LocalAddr().String())
	sess := NewSession("smb", "tcp", host, port, destPort, t.logger)

	if !t.limiter.Acquire(host) {
		LogRejected(t.logger, "smb", "tcp", destPort, host, "rate_limit")
		return
	}
	defer t.limiter.Release(host)

	sess.LogConnect()
	sess.RecordStart(t.metrics)
	defer sess.RecordEnd(t.metrics)
	defer sess.LogDisconnect()

	_ = conn.SetDeadline(deadlineFromContext(ctx, t.cfg.SessionTimeout))

	for {
		payload, err := smbReadMessage(conn)
		if err != nil {
			if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() {
				sess.SetOutcome("timeout")
			} else {
				sess.SetOutcome("error")
			}
			return
		}

		if len(payload) < 4 {
			return
		}

		if payload[0] == 0xFF && payload[1] == 'S' && payload[2] == 'M' && payload[3] == 'B' {
			t.handleSMB1Negotiate(conn)
			return
		}

		if payload[0] == 0xFE && payload[1] == 'S' && payload[2] == 'M' && payload[3] == 'B' {
			if len(payload) < 16 {
				return
			}
			command := binary.LittleEndian.Uint16(payload[12:14])
			switch command {
			case 0x0000: // Negotiate
				if err := t.handleSMB2Negotiate(conn, payload); err != nil {
					return
				}
			case 0x0001: // Session Setup
				t.handleSMB2SessionSetup(ctx, conn, host, sess, payload)
				return
			default:
				return
			}
		}
	}
}

func (t *SMBTrap) handleSMB1Negotiate(conn net.Conn) {
	header := make([]byte, 32)
	header[0] = 0xFF
	copy(header[1:4], []byte("SMB"))
	header[4] = 0x72 // Negotiate
	// Status: success
	// Flags
	header[13] = 0x98
	header[14] = 0x01

	dialectIndex := []byte{0x00, 0x00} // select first dialect
	params := make([]byte, 1+2)
	params[0] = 1 // word count = 1 (2 bytes of params / 2)
	copy(params[1:], dialectIndex)

	data := []byte{0x00, 0x00} // byte count = 0

	resp := append(header, params...)
	resp = append(resp, data...)
	_ = smbWriteMessage(conn, resp)
}

func (t *SMBTrap) handleSMB2Negotiate(conn net.Conn, _ []byte) error {
	resp := make([]byte, 64+65)

	// SMB2 header (64 bytes)
	resp[0] = 0xFE
	copy(resp[1:4], []byte("SMB"))
	binary.LittleEndian.PutUint16(resp[4:6], 64) // StructureSize
	// Command: Negotiate (0x0000)
	binary.LittleEndian.PutUint16(resp[12:14], 0x0000)
	// Status: SUCCESS
	// Flags: Response
	binary.LittleEndian.PutUint32(resp[16:20], 0x00000001)
	// MessageId
	binary.LittleEndian.PutUint64(resp[28:36], 0)

	// Negotiate response body (starts at offset 64)
	body := resp[64:]
	binary.LittleEndian.PutUint16(body[0:2], 65) // StructureSize
	// SecurityMode
	binary.LittleEndian.PutUint16(body[2:4], 0x0001)
	// DialectRevision: 0x0210 (SMB 2.1)
	binary.LittleEndian.PutUint16(body[4:6], 0x0210)
	// MaxTransactSize, MaxReadSize, MaxWriteSize
	binary.LittleEndian.PutUint32(body[12:16], 65536)
	binary.LittleEndian.PutUint32(body[16:20], 65536)
	binary.LittleEndian.PutUint32(body[20:24], 65536)

	// SecurityBufferOffset and Length (no NTLMSSP challenge in negotiate for simplicity)
	binary.LittleEndian.PutUint16(body[56:58], 0) // SecurityBufferOffset
	binary.LittleEndian.PutUint16(body[58:60], 0) // SecurityBufferLength

	return smbWriteMessage(conn, resp)
}

func (t *SMBTrap) handleSMB2SessionSetup(ctx context.Context, conn net.Conn, host string, sess *Session, payload []byte) {
	if len(payload) < 64+24 {
		t.sendSessionSetupFailure(conn, payload)
		return
	}

	body := payload[64:]
	secBufOffset := int(binary.LittleEndian.Uint16(body[12:14]))
	secBufLen := int(binary.LittleEndian.Uint16(body[14:16]))

	headerOffset := secBufOffset - 64 // offset relative to body start... actually offset from start of SMB2 header
	// SecurityBufferOffset is from the beginning of the SMB2 header
	if secBufOffset < 64 || secBufOffset+secBufLen > len(payload) {
		t.sendSessionSetupFailure(conn, payload)
		return
	}

	secBuf := payload[secBufOffset : secBufOffset+secBufLen]
	_ = headerOffset

	domain, username, workstation := parseNTLMSSPAuth(secBuf)

	user := username
	if domain != "" {
		user = domain + `\` + username
	}

	sess.LogAuthAttempt(
		slog.String("username", user),
		slog.String("workstation", workstation),
	)
	sess.RecordCredentials(t.metrics)
	t.alerter.Alert(ctx, host, "smb", map[string]string{"username": user, "domain": domain, "workstation": workstation})

	t.sendSessionSetupFailure(conn, payload)
}

func (t *SMBTrap) sendSessionSetupFailure(conn net.Conn, req []byte) {
	resp := make([]byte, 64+9)

	resp[0] = 0xFE
	copy(resp[1:4], []byte("SMB"))
	binary.LittleEndian.PutUint16(resp[4:6], 64) // StructureSize
	binary.LittleEndian.PutUint16(resp[12:14], 0x0001) // Command: Session Setup
	// Status: STATUS_LOGON_FAILURE
	binary.LittleEndian.PutUint32(resp[8:12], 0xC000006D)
	// Flags: Response
	binary.LittleEndian.PutUint32(resp[16:20], 0x00000001)

	if len(req) >= 36 {
		copy(resp[28:36], req[28:36]) // copy MessageId
	}

	body := resp[64:]
	binary.LittleEndian.PutUint16(body[0:2], 9) // StructureSize

	_ = smbWriteMessage(conn, resp)
}

func smbReadMessage(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	// NetBIOS: type byte + 3-byte length (big-endian)
	length := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	if length == 0 || length > 1<<20 {
		return nil, fmt.Errorf("smb: invalid message length %d", length)
	}
	payload := make([]byte, length)
	_, err := io.ReadFull(r, payload)
	return payload, err
}

func smbWriteMessage(w io.Writer, data []byte) error {
	var hdr [4]byte
	hdr[0] = 0x00 // session message
	length := len(data)
	hdr[1] = byte(length >> 16)
	hdr[2] = byte(length >> 8)
	hdr[3] = byte(length)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

func parseNTLMSSPAuth(data []byte) (domain, username, workstation string) {
	// Look for NTLMSSP signature
	sig := []byte("NTLMSSP\x00")
	idx := -1
	for i := 0; i <= len(data)-8; i++ {
		match := true
		for j := 0; j < 8; j++ {
			if data[i+j] != sig[j] {
				match = false
				break
			}
		}
		if match {
			idx = i
			break
		}
	}
	if idx < 0 {
		return
	}
	ntlm := data[idx:]

	if len(ntlm) < 12 {
		return
	}
	msgType := binary.LittleEndian.Uint32(ntlm[8:12])
	if msgType != 3 { // NTLMSSP_AUTH
		return
	}

	if len(ntlm) < 44 {
		return
	}

	domain = ntlmsspReadField(ntlm, 28)
	username = ntlmsspReadField(ntlm, 36)
	workstation = ntlmsspReadField(ntlm, 44)
	return
}

func ntlmsspReadField(data []byte, offset int) string {
	if offset+4 > len(data) {
		return ""
	}
	length := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
	if offset+8 > len(data) {
		return ""
	}
	bufOffset := int(binary.LittleEndian.Uint32(data[offset+4 : offset+8]))
	if bufOffset+length > len(data) || length == 0 {
		return ""
	}
	field := data[bufOffset : bufOffset+length]

	// Try UTF-16LE decode
	if length >= 2 && length%2 == 0 {
		u16 := make([]uint16, length/2)
		for i := range u16 {
			u16[i] = binary.LittleEndian.Uint16(field[i*2 : i*2+2])
		}
		return string(utf16.Decode(u16))
	}
	return string(field)
}
