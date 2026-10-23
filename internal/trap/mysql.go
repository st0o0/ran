package trap

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync/atomic"

	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

type MySQLTrap struct {
	*tcpServer
	cfg     *config.Config
	logger  *slog.Logger
	metrics *metrics.Metrics
	connID  atomic.Uint32
}

func NewMySQL(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter Reporter) *MySQLTrap {
	t := &MySQLTrap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
	}
	t.tcpServer = newTCPServer("mysql", cfg, logger, m, limiter, alerter, t.handle)
	return t
}

func (t *MySQLTrap) handle(ctx context.Context, conn net.Conn, sess *Session) {
	challenge := make([]byte, 20)
	rand.Read(challenge)

	connID := t.connID.Add(1)
	greeting := buildGreeting(connID, challenge)
	if _, err := conn.Write(greeting); err != nil {
		setOutcome(sess, err)
		return
	}

	response, err := readMySQLPacket(conn)
	if err != nil {
		setOutcome(sess, err)
		return
	}

	username, password := parseHandshakeResponse(response, challenge)
	sess.Cred(ctx, t.metrics, username, password)

	_, _ = conn.Write(buildErrPacket(2, 1045, "28000", "Access denied for user '"+username+"'"))
}

func buildGreeting(connID uint32, challenge []byte) []byte {
	serverVersion := "8.0.36\x00"
	authPlugin := "mysql_clear_password\x00"

	// Protocol version 10, server version, connection id, challenge part 1 (8 bytes),
	// filler, capability flags, charset, status, more capabilities, auth plugin len,
	// reserved, challenge part 2, auth plugin name
	var payload []byte
	payload = append(payload, 10) // protocol version
	payload = append(payload, []byte(serverVersion)...)
	payload = binary.LittleEndian.AppendUint32(payload, connID)
	payload = append(payload, challenge[:8]...)
	payload = append(payload, 0) // filler

	// Capability flags (lower 2 bytes): CLIENT_LONG_PASSWORD | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH
	capLow := uint16(0x0001 | 0x0200 | 0x8000 | 0x00080000>>16)
	payload = binary.LittleEndian.AppendUint16(payload, capLow)

	payload = append(payload, 0x21)                             // charset utf8
	payload = binary.LittleEndian.AppendUint16(payload, 0x0002) // status: autocommit

	// Upper capability flags
	payload = binary.LittleEndian.AppendUint16(payload, 0x0008) // CLIENT_PLUGIN_AUTH high bit

	payload = append(payload, byte(len(challenge)+1)) // auth plugin data length
	payload = append(payload, make([]byte, 10)...)    // reserved

	payload = append(payload, challenge[8:]...) // challenge part 2 (12 bytes)
	payload = append(payload, 0)                // null terminator
	payload = append(payload, []byte(authPlugin)...)

	return wrapMySQLPacket(0, payload)
}

func buildErrPacket(seq byte, code uint16, state, msg string) []byte {
	var payload []byte
	payload = append(payload, 0xFF) // ERR marker
	payload = binary.LittleEndian.AppendUint16(payload, code)
	payload = append(payload, '#')
	payload = append(payload, []byte(state)...)
	payload = append(payload, []byte(msg)...)
	return wrapMySQLPacket(seq, payload)
}

func wrapMySQLPacket(seq byte, payload []byte) []byte {
	pkt := make([]byte, 4+len(payload))
	pkt[0] = byte(len(payload))
	pkt[1] = byte(len(payload) >> 8)
	pkt[2] = byte(len(payload) >> 16)
	pkt[3] = seq
	copy(pkt[4:], payload)
	return pkt
}

func readMySQLPacket(r io.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	length := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if length > 1<<20 {
		return nil, fmt.Errorf("packet too large: %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func parseHandshakeResponse(data []byte, _ []byte) (username, password string) {
	if len(data) < 32 {
		return "", ""
	}

	// Skip: client capabilities (4) + max packet (4) + charset (1) + reserved (23) = 32
	pos := 32

	// Username: null-terminated string
	usernameEnd := pos
	for usernameEnd < len(data) && data[usernameEnd] != 0 {
		usernameEnd++
	}
	username = string(data[pos:usernameEnd])
	pos = usernameEnd + 1

	if pos >= len(data) {
		return username, ""
	}

	// Auth response: length-prefixed or null-terminated
	authLen := int(data[pos])
	pos++
	if pos+authLen > len(data) {
		return username, ""
	}
	authData := data[pos : pos+authLen]

	// mysql_clear_password sends plaintext
	password = string(authData)
	// Strip trailing null if present
	if len(password) > 0 && password[len(password)-1] == 0 {
		password = password[:len(password)-1]
	}

	return username, password
}
