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

type MQTTTrap struct {
	*tcpServer
	cfg     *config.Config
	logger  *slog.Logger
	metrics *metrics.Metrics
}

func NewMQTT(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter Reporter) *MQTTTrap {
	t := &MQTTTrap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
	}
	t.tcpServer = newTCPServer("mqtt", cfg, logger, m, limiter, alerter, t.handle)
	return t
}

func (t *MQTTTrap) handle(ctx context.Context, conn net.Conn, sess *Session) {
	packetType, payload, err := readMQTTPacket(conn)
	if err != nil {
		setOutcome(sess, err)
		return
	}

	if packetType != 1 {
		sess.SetOutcome("error")
		return
	}

	clientID, username, password, protocolLevel, err := parseMQTTConnect(payload)
	if err != nil {
		sess.SetOutcome("error")
		return
	}

	sess.LogAuthAttempt(
		slog.String("client_id", clientID),
		slog.String("username", username),
		slog.String("password", password),
	)
	sess.RecordCredentials(t.metrics)
	sess.Alert(ctx, map[string]string{"client_id": clientID, "username": username, "password": password, "kind": "connect"})

	_, _ = conn.Write(buildMQTTConnack(protocolLevel))
}

func readMQTTPacket(r io.Reader) (packetType byte, payload []byte, err error) {
	var header [1]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	packetType = header[0] >> 4

	remainingLength, err := readMQTTVarInt(r)
	if err != nil {
		return 0, nil, err
	}
	if remainingLength > 1<<20 {
		return 0, nil, fmt.Errorf("packet too large: %d", remainingLength)
	}

	payload = make([]byte, remainingLength)
	if remainingLength > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
	}
	return packetType, payload, nil
}

func readMQTTVarInt(r io.Reader) (int, error) {
	var value int
	var multiplier = 1
	var b [1]byte
	for i := 0; i < 4; i++ {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, err
		}
		value += int(b[0]&0x7F) * multiplier
		if b[0]&0x80 == 0 {
			return value, nil
		}
		multiplier *= 128
	}
	return 0, fmt.Errorf("malformed variable length encoding")
}

func parseMQTTConnect(data []byte) (clientID, username, password string, protocolLevel byte, err error) {
	if len(data) < 10 {
		return "", "", "", 0, fmt.Errorf("connect packet too short")
	}

	pos := 0

	// Protocol name: 2-byte length + string
	protoLen := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2
	if pos+protoLen > len(data) {
		return "", "", "", 0, fmt.Errorf("invalid protocol name length")
	}
	protoName := string(data[pos : pos+protoLen])
	pos += protoLen

	if protoName != "MQTT" && protoName != "MQIsdp" {
		return "", "", "", 0, fmt.Errorf("unknown protocol: %s", protoName)
	}

	if pos+4 > len(data) {
		return "", "", "", 0, fmt.Errorf("connect packet truncated")
	}

	protocolLevel = data[pos]
	pos++

	connectFlags := data[pos]
	pos++

	hasUsername := connectFlags&0x80 != 0
	hasPassword := connectFlags&0x40 != 0

	// Skip keep alive (2 bytes)
	pos += 2

	// MQTT 5: skip properties
	if protocolLevel == 5 {
		if pos >= len(data) {
			return "", "", "", protocolLevel, fmt.Errorf("missing properties length")
		}
		propsLen, n, err := decodeMQTTVarIntFromBytes(data[pos:])
		if err != nil {
			return "", "", "", protocolLevel, err
		}
		pos += n + propsLen
	}

	// Client ID
	clientID, pos, err = readMQTTString(data, pos)
	if err != nil {
		return "", "", "", protocolLevel, fmt.Errorf("reading client_id: %w", err)
	}

	if hasUsername {
		username, pos, err = readMQTTString(data, pos)
		if err != nil {
			return clientID, "", "", protocolLevel, nil
		}
	}

	if hasPassword {
		password, _, err = readMQTTString(data, pos)
		if err != nil {
			return clientID, username, "", protocolLevel, nil
		}
	}

	return clientID, username, password, protocolLevel, nil
}

func readMQTTString(data []byte, pos int) (string, int, error) {
	if pos+2 > len(data) {
		return "", pos, fmt.Errorf("string length out of bounds")
	}
	length := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2
	if pos+length > len(data) {
		return "", pos, fmt.Errorf("string data out of bounds")
	}
	return string(data[pos : pos+length]), pos + length, nil
}

func decodeMQTTVarIntFromBytes(data []byte) (int, int, error) {
	var value int
	var multiplier = 1
	for i := 0; i < 4 && i < len(data); i++ {
		value += int(data[i]&0x7F) * multiplier
		if data[i]&0x80 == 0 {
			return value, i + 1, nil
		}
		multiplier *= 128
	}
	return 0, 0, fmt.Errorf("malformed variable length encoding")
}

func buildMQTTConnack(protocolLevel byte) []byte {
	if protocolLevel == 5 {
		// MQTT 5: CONNACK with reason code 0x86 (bad username or password) + zero property length
		return []byte{0x20, 3, 0x00, 0x86, 0x00}
	}
	// MQTT 3.x: CONNACK with return code 4 (bad username or password)
	return []byte{0x20, 2, 0x00, 0x04}
}
