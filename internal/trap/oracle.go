package trap

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"

	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

type OracleTrap struct {
	*tcpServer
	cfg     *config.Config
	logger  *slog.Logger
	metrics *metrics.Metrics
}

func NewOracle(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter Reporter) *OracleTrap {
	t := &OracleTrap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
	}
	t.tcpServer = newTCPServer("oracle", cfg, logger, m, limiter, alerter, t.handle)
	return t
}

func (t *OracleTrap) handle(ctx context.Context, conn net.Conn, sess *Session) {
	pktType, payload, err := readTNSPacket(conn)
	if err != nil {
		setOutcome(sess, err)
		return
	}

	if pktType != 1 {
		sess.SetOutcome("error")
		return
	}

	connectData := string(payload)
	username := extractTNSParam(connectData, "USER")
	serviceName := extractTNSParam(connectData, "SERVICE_NAME")

	acceptPayload := make([]byte, 16)
	binary.BigEndian.PutUint16(acceptPayload[0:2], 0x0139)
	binary.BigEndian.PutUint16(acceptPayload[4:6], 0x0800)
	binary.BigEndian.PutUint16(acceptPayload[6:8], 0x0800)
	if _, err := conn.Write(buildTNSPacket(2, acceptPayload)); err != nil {
		setOutcome(sess, err)
		return
	}

	sess.LogAuthAttempt(
		slog.String("username", username),
		slog.String("service_name", serviceName),
	)
	sess.RecordCredentials(t.metrics)
	sess.Alert(ctx, map[string]string{"username": username, "service_name": serviceName})

	refuseMsg := "ORA-01017: invalid username/password; logon denied"
	refuseData := make([]byte, 4+len(refuseMsg))
	refuseData[0] = 1
	refuseData[1] = 0
	binary.BigEndian.PutUint16(refuseData[2:4], uint16(len(refuseMsg)))
	copy(refuseData[4:], refuseMsg)
	_, _ = conn.Write(buildTNSPacket(4, refuseData))
}

func readTNSPacket(r io.Reader) (pktType byte, payload []byte, err error) {
	header := make([]byte, 8)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}
	length := int(binary.BigEndian.Uint16(header[0:2]))
	if length < 8 || length > 1<<20 {
		return 0, nil, fmt.Errorf("invalid TNS packet length: %d", length)
	}
	pktType = header[4]
	payload = make([]byte, length-8)
	if len(payload) > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
	}
	return pktType, payload, nil
}

func buildTNSPacket(pktType byte, payload []byte) []byte {
	pkt := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(pkt[0:2], uint16(8+len(payload)))
	pkt[4] = pktType
	copy(pkt[8:], payload)
	return pkt
}

func extractTNSParam(data, key string) string {
	search := "(" + key + "="
	idx := strings.Index(strings.ToUpper(data), strings.ToUpper(search))
	if idx < 0 {
		return ""
	}
	start := idx + len(search)
	end := strings.Index(data[start:], ")")
	if end < 0 {
		return ""
	}
	return data[start : start+end]
}
