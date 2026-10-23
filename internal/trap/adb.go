package trap

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"

	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

const (
	adbCmdCNXN = 0x4e584e43
	adbCmdAUTH = 0x48545541
	adbHdrSize = 24
)

type ADBTrap struct {
	*tcpServer
	cfg     *config.Config
	logger  *slog.Logger
	metrics *metrics.Metrics
}

func NewADB(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter Reporter) *ADBTrap {
	t := &ADBTrap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
	}
	t.tcpServer = newTCPServer("adb", cfg, logger, m, limiter, alerter, t.handle)
	return t
}

func (t *ADBTrap) handle(ctx context.Context, conn net.Conn, sess *Session) {
	hdr := make([]byte, adbHdrSize)
	if _, err := readFull(conn, hdr); err != nil {
		setOutcome(sess, err)
		return
	}

	cmd := binary.LittleEndian.Uint32(hdr[0:4])
	if cmd != adbCmdCNXN {
		sess.LogPayload("adb_unknown", slog.String("raw", fmt.Sprintf("%x", hdr)))
		return
	}

	dataLen := binary.LittleEndian.Uint32(hdr[12:16])
	if dataLen > 4096 {
		dataLen = 4096
	}

	var identity string
	if dataLen > 0 {
		payload := make([]byte, dataLen)
		if _, err := readFull(conn, payload); err == nil {
			identity = string(payload)
		}
	}

	sess.LogPayload("adb_identity", slog.String("identity", identity))
	sess.Alert(ctx, map[string]string{"identity": identity})

	token := make([]byte, 20)
	_, _ = rand.Read(token)

	resp := make([]byte, adbHdrSize+len(token))
	binary.LittleEndian.PutUint32(resp[0:4], adbCmdAUTH)
	binary.LittleEndian.PutUint32(resp[4:8], 1) // AUTH_TOKEN
	binary.LittleEndian.PutUint32(resp[8:12], 0)
	binary.LittleEndian.PutUint32(resp[12:16], uint32(len(token)))
	copy(resp[adbHdrSize:], token)

	_, _ = conn.Write(resp)
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
