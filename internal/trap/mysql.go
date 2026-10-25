package trap

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"

	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/fingerprint"
	"github.com/st0o0/ran/internal/metrics"
)

type MySQLTrap struct {
	*tcpServer
	cfg     *config.Config
	logger  *slog.Logger
	metrics *metrics.Metrics
	connID  atomic.Uint32
	fp      *fingerprint.Profile
}

func NewMySQL(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter Reporter) *MySQLTrap {
	t := &MySQLTrap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
		fp:      cfg.Fingerprint(logger),
	}
	t.tcpServer = newTCPServer("mysql", cfg, logger, m, limiter, alerter, t.handle)
	return t
}

func (t *MySQLTrap) handle(ctx context.Context, conn net.Conn, sess *Session) {
	challenge := make([]byte, 20)
	rand.Read(challenge)

	// Fixed mode keeps the original greeting byte for byte; seeded mode presents
	// the greeting of the profile's MySQL generation.
	realistic := t.fp.Mode == fingerprint.ModeSeeded

	connID := t.connID.Add(1)
	greeting := buildGreeting(t.fp.MySQL, connID, challenge)
	if realistic {
		for i, b := range challenge {
			if b == 0 { // mysqld never puts a NUL byte into the scramble
				challenge[i] = 1 + byte(connID%254)
			}
		}
		greeting = buildRealisticGreeting(t.fp.MySQL, connID, challenge)
	}
	if _, err := conn.Write(greeting); err != nil {
		setOutcome(sess, err)
		return
	}

	response, err := readMySQLPacket(conn)
	if err != nil {
		setOutcome(sess, err)
		return
	}

	maxRetries := t.cfg.ResolveMaxAuthRetries("mysql")
	authDelay := t.cfg.ResolveAuthDelay("mysql")

	username, password := parseHandshakeResponse(response, challenge)
	if realistic {
		switch mysqlClientPluginName(response) {
		case "mysql_native_password", "caching_sha2_password", "sha256_password":
			// A scramble, not a password: the clear text comes with the switch.
			password = ""
		}
	}
	// An authentication switch needs CLIENT_PLUGIN_AUTH; without it the client
	// cannot parse the request, so the session stays a single attempt.
	canSwitch := mysqlClientPluginAuth(response)
	seq := byte(1) // sequence number of the last packet received
	// Every iteration blocks on a client read (bounded by the session deadline)
	// and, with an auth delay, on authSleep, so unlimited retries cannot spin.
	for attempt := 0; ; attempt++ {
		sess.Cred(ctx, t.metrics, username, password)
		prev := password

		if authDelay > 0 {
			if err := sess.authSleep(ctx, authDelay, attempt); err != nil {
				sess.SetOutcome("timeout")
				return
			}
		}

		if !canSwitch || (maxRetries != 0 && attempt+1 >= maxRetries) {
			_, _ = conn.Write(buildErrPacket(seq+1, 1045, "28000", "Access denied for user '"+username+"'"))
			return
		}

		// Ask for another password with an authentication switch to
		// mysql_clear_password; the client answers with the password and a NUL.
		if _, err := conn.Write(buildAuthSwitchRequest(seq + 1)); err != nil {
			setOutcome(sess, err)
			return
		}
		reply, err := readMySQLPacket(conn)
		if err != nil {
			sess.setReadOutcome(err)
			return
		}
		seq += 2
		password = parseAuthSwitchReply(reply)
		// A client that resends the same stored password is not a new attempt.
		if password == prev {
			_, _ = conn.Write(buildErrPacket(seq+1, 1045, "28000", "Access denied for user '"+username+"'"))
			return
		}
	}
}

// mysqlClientPluginAuth reports whether the handshake response sets
// CLIENT_PLUGIN_AUTH (0x00080000) in its capability flags.
func mysqlClientPluginAuth(response []byte) bool {
	return len(response) >= 4 && binary.LittleEndian.Uint32(response[:4])&0x00080000 != 0
}

// buildAuthSwitchRequest asks the client to authenticate again with
// mysql_clear_password.
func buildAuthSwitchRequest(seq byte) []byte {
	payload := append([]byte{0xFE}, "mysql_clear_password\x00"...)
	return wrapMySQLPacket(seq, payload)
}

// maxMySQLPassword bounds a password taken from an authentication switch reply.
const maxMySQLPassword = 4096

// parseAuthSwitchReply returns the clear text password of an authentication
// switch reply: the packet without its trailing NUL, cut to maxMySQLPassword.
func parseAuthSwitchReply(data []byte) string {
	data = bytes.TrimSuffix(data, []byte{0})
	if len(data) > maxMySQLPassword {
		data = data[:maxMySQLPassword]
	}
	return string(data)
}

func buildGreeting(version string, connID uint32, challenge []byte) []byte {
	serverVersion := version + "\x00"
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

// mysqlGreetingStyle holds what differs between the greetings of MySQL 5.7 and
// 8.0 servers.
type mysqlGreetingStyle struct {
	capLow, capHigh uint16
	charset         byte
	plugin          string
}

// mysqlStyleFor returns the greeting style of a server version string. Server
// capability flags are those of a mysqld without TLS configured (no CLIENT_SSL),
// because the trap cannot upgrade a connection to TLS.
//   - 8.0: 0xf7ff / 0xc3ff, utf8mb4_0900_ai_ci (255), caching_sha2_password.
//   - 5.7: 0xf7ff / 0x807f, latin1_swedish_ci (8) as the 5.7 default
//     character_set_server, mysql_native_password.
//
// The upper 5.7 flags are from memory of captured greetings, not verified.
func mysqlStyleFor(version string) mysqlGreetingStyle {
	if strings.HasPrefix(version, "5.") {
		return mysqlGreetingStyle{capLow: 0xf7ff, capHigh: 0x807f, charset: 0x08, plugin: "mysql_native_password"}
	}
	return mysqlGreetingStyle{capLow: 0xf7ff, capHigh: 0xc3ff, charset: 0xff, plugin: "caching_sha2_password"}
}

// buildRealisticGreeting is the greeting of a real server of the version's
// generation. The trap still gets the password: it asks for it with an
// authentication switch to mysql_clear_password after the client's scramble.
func buildRealisticGreeting(version string, connID uint32, challenge []byte) []byte {
	st := mysqlStyleFor(version)
	var payload []byte
	payload = append(payload, 10)
	payload = append(payload, []byte(version+"\x00")...)
	payload = binary.LittleEndian.AppendUint32(payload, connID)
	payload = append(payload, challenge[:8]...)
	payload = append(payload, 0) // filler
	payload = binary.LittleEndian.AppendUint16(payload, st.capLow)
	payload = append(payload, st.charset)
	payload = binary.LittleEndian.AppendUint16(payload, 0x0002) // status: autocommit
	payload = binary.LittleEndian.AppendUint16(payload, st.capHigh)
	payload = append(payload, byte(len(challenge)+1)) // auth plugin data length
	payload = append(payload, make([]byte, 10)...)    // reserved
	payload = append(payload, challenge[8:]...)
	payload = append(payload, 0)
	payload = append(payload, []byte(st.plugin+"\x00")...)
	return wrapMySQLPacket(0, payload)
}

// mysqlClientPluginName returns the auth plugin name of a handshake response
// (HandshakeResponse41), or "" when it has none or cannot be located. It only
// reads, bounded by the packet.
func mysqlClientPluginName(data []byte) string {
	if len(data) < 33 {
		return ""
	}
	caps := binary.LittleEndian.Uint32(data[:4])
	if caps&0x00080000 == 0 { // CLIENT_PLUGIN_AUTH
		return ""
	}
	nul := func(pos int) int { // index of the NUL at or after pos, or -1
		if pos > len(data) {
			return -1
		}
		i := bytes.IndexByte(data[pos:], 0)
		if i < 0 {
			return -1
		}
		return pos + i
	}
	end := nul(32)
	if end < 0 {
		return ""
	}
	pos := end + 1
	switch {
	case caps&0x00200000 != 0: // CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
		if pos >= len(data) || data[pos] >= 251 {
			return ""
		}
		pos += 1 + int(data[pos])
	case caps&0x8000 != 0: // CLIENT_SECURE_CONNECTION
		if pos >= len(data) {
			return ""
		}
		pos += 1 + int(data[pos])
	default:
		e := nul(pos)
		if e < 0 {
			return ""
		}
		pos = e + 1
	}
	if caps&0x8 != 0 { // CLIENT_CONNECT_WITH_DB
		e := nul(pos)
		if e < 0 {
			return ""
		}
		pos = e + 1
	}
	if pos >= len(data) {
		return ""
	}
	e := nul(pos)
	if e < 0 {
		e = len(data)
	}
	if e-pos > 64 {
		return ""
	}
	return string(data[pos:e])
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
