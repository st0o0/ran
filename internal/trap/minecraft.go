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
	"sync"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

type MinecraftTrap struct {
	cfg      *config.Config
	logger   *slog.Logger
	metrics  *metrics.Metrics
	limiter  *Limiter
	alerter  alert.Alerter
	listener *MultiListener
	wg       sync.WaitGroup
}

func NewMinecraft(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) *MinecraftTrap {
	return &MinecraftTrap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
		limiter: limiter,
		alerter: alerter,
	}
}

func (t *MinecraftTrap) Start(ctx context.Context) error {
	ln, err := ListenMultiTCP(ctx, t.cfg.TrapAddrs("minecraft"), t.cfg.ProxyProtocol)
	if err != nil {
		return fmt.Errorf("minecraft listen: %w", err)
	}
	t.listener = ln
	t.logger.Info("listening", "addrs", t.cfg.TrapAddrs("minecraft"))

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
			LogErrorStandalone(t.logger, "minecraft", "accept_failed", err)
			continue
		}
		t.wg.Add(1)
		go t.handle(ctx, conn)
	}
	return nil
}

func (t *MinecraftTrap) Stop(_ context.Context) error {
	if t.listener != nil {
		t.listener.Close()
	}
	t.wg.Wait()
	return nil
}

func (t *MinecraftTrap) handle(ctx context.Context, conn net.Conn) {
	defer t.wg.Done()
	defer conn.Close()

	host, port := ParseAddr(conn.RemoteAddr().String())
	_, destPort := ParseAddr(conn.LocalAddr().String())
	sess := NewSession("minecraft", "tcp", host, port, destPort, t.logger)

	if !t.limiter.Acquire(host) {
		LogRejected(t.logger, "minecraft", "tcp", destPort, host, "rate_limit")
		return
	}
	defer t.limiter.Release(host)

	sess.LogConnect()
	sess.RecordStart(t.metrics)
	defer sess.RecordEnd(t.metrics)
	defer sess.LogDisconnect()

	_ = conn.SetDeadline(deadlineFromContext(ctx, t.cfg.SessionTimeout))

	r := bufio.NewReader(conn)

	payload, err := mcReadPacket(r)
	if err != nil || len(payload) < 1 || payload[0] != 0x00 {
		if err != nil {
			if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() {
				sess.SetOutcome("timeout")
			} else {
				sess.SetOutcome("error")
			}
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

	sess.LogPayload("mc_handshake",
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

	t.alerter.Alert(ctx, host, "minecraft", meta)
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
