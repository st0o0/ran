package trap

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"

	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

type MinecraftTrap struct {
	*tcpServer
	cfg     *config.Config
	logger  *slog.Logger
	metrics *metrics.Metrics
}

func NewMinecraft(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter Reporter) *MinecraftTrap {
	t := &MinecraftTrap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
	}
	t.tcpServer = newTCPServer("minecraft", cfg, logger, m, limiter, alerter, t.handle)
	return t
}

func (t *MinecraftTrap) handle(ctx context.Context, conn net.Conn, sess *Session) {
	r := bufio.NewReader(conn)

	payload, err := mcReadPacket(r)
	if err != nil || len(payload) < 1 || payload[0] != 0x00 {
		if err != nil {
			setOutcome(sess, err)
		} else {
			sess.SetOutcome("error")
		}
		return
	}
	payload = payload[1:]

	protocolVersion, pvSize := mcReadVarint(payload)
	if pvSize == 0 {
		return
	}
	payload = payload[pvSize:]

	serverAddr, saSize := mcReadString(payload)
	if saSize == 0 {
		return
	}
	payload = payload[saSize:]

	if len(payload) < 3 {
		return
	}
	serverPort := binary.BigEndian.Uint16(payload[:2])
	payload = payload[2:]

	nextState, nsSize := mcReadVarint(payload)
	if nsSize == 0 {
		return
	}

	// The handshake and a server-list ping (next_state 1) are not an attack; only a
	// login attempt with a player name counts as payload (see handleLogin).
	sess.Log("handshake received",
		slog.String("payload_type", "mc_handshake"),
		slog.Int("protocol_version", int(protocolVersion)),
		slog.String("server_address", serverAddr),
		slog.Int("server_port", int(serverPort)),
		slog.Int("next_state", int(nextState)),
	)

	meta := map[string]string{
		"protocol_version": strconv.Itoa(int(protocolVersion)),
		"server_address":   serverAddr,
	}

	switch nextState {
	case 1:
		t.handleStatus(conn, r, sess)
	case 2:
		t.handleLogin(conn, r, sess, meta)
	}

	sess.Alert(ctx, meta)
}

func (t *MinecraftTrap) handleStatus(conn net.Conn, r *bufio.Reader, sess *Session) {
	payload, err := mcReadPacket(r)
	if err != nil || len(payload) < 1 || payload[0] != 0x00 {
		return
	}

	statusJSON := `{"version":{"name":"1.21.4","protocol":767},"players":{"max":20,"online":0},"description":{"text":"A Minecraft Server"}}`
	_, _ = conn.Write(mcWritePacket(0x00, mcWriteString(statusJSON)))

	payload, err = mcReadPacket(r)
	if err != nil || len(payload) < 9 || payload[0] != 0x01 {
		return
	}
	_, _ = conn.Write(mcWritePacket(0x01, payload[1:9]))
}

func (t *MinecraftTrap) handleLogin(conn net.Conn, r *bufio.Reader, sess *Session, meta map[string]string) {
	payload, err := mcReadPacket(r)
	if err != nil || len(payload) < 2 || payload[0] != 0x00 {
		return
	}

	playerName, _ := mcReadString(payload[1:])
	if playerName != "" {
		sess.LogPayload("mc_login", slog.String("player_name", playerName))
		meta["player_name"] = playerName
	}

	reason := `{"text":"Server is under maintenance"}`
	_, _ = conn.Write(mcWritePacket(0x00, mcWriteString(reason)))
}

func mcReadPacket(r *bufio.Reader) ([]byte, error) {
	length, err := mcReadVarintFromReader(r)
	if err != nil || length < 1 || length > 32767 {
		return nil, fmt.Errorf("invalid packet length: %d", length)
	}
	payload := make([]byte, length)
	_, err = io.ReadFull(r, payload)
	return payload, err
}

func mcReadVarintFromReader(r *bufio.Reader) (int32, error) {
	var result int32
	for i := 0; i < 5; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		result |= int32(b&0x7F) << (7 * i)
		if b&0x80 == 0 {
			return result, nil
		}
	}
	return 0, fmt.Errorf("varint too long")
}

func mcReadVarint(data []byte) (int32, int) {
	var result int32
	for i := 0; i < 5 && i < len(data); i++ {
		b := data[i]
		result |= int32(b&0x7F) << (7 * i)
		if b&0x80 == 0 {
			return result, i + 1
		}
	}
	return 0, 0
}

func mcWriteVarint(val int32) []byte {
	var buf []byte
	for {
		b := byte(val & 0x7F)
		val >>= 7
		if val != 0 {
			b |= 0x80
		}
		buf = append(buf, b)
		if val == 0 {
			break
		}
	}
	return buf
}

func mcReadString(data []byte) (string, int) {
	length, lSize := mcReadVarint(data)
	if lSize == 0 || length < 0 || int(length) > len(data)-lSize {
		return "", 0
	}
	return string(data[lSize : lSize+int(length)]), lSize + int(length)
}

func mcWriteString(s string) []byte {
	length := mcWriteVarint(int32(len(s)))
	return append(length, []byte(s)...)
}

func mcWritePacket(packetID byte, payload []byte) []byte {
	inner := append([]byte{packetID}, payload...)
	length := mcWriteVarint(int32(len(inner)))
	return append(length, inner...)
}
