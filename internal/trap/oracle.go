package trap

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

type OracleTrap struct {
	cfg      *config.Config
	logger   *slog.Logger
	metrics  *metrics.Metrics
	limiter  *Limiter
	alerter  alert.Alerter
	listener *MultiListener
	wg       sync.WaitGroup
}

func NewOracle(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) *OracleTrap {
	return &OracleTrap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
		limiter: limiter,
		alerter: alerter,
	}
}

func (t *OracleTrap) Start(ctx context.Context) error {
	ln, err := ListenMultiTCP(ctx, t.cfg.TrapAddrs("oracle"), t.cfg.ProxyProtocol)
	if err != nil {
		return fmt.Errorf("oracle listen: %w", err)
	}
	t.listener = ln
	t.logger.Info("listening", "addrs", t.cfg.TrapAddrs("oracle"))

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
			LogErrorStandalone(t.logger, "oracle", "accept_failed", err)
			continue
		}
		t.wg.Add(1)
		go t.handle(ctx, conn)
	}
	return nil
}

func (t *OracleTrap) Stop(_ context.Context) error {
	if t.listener != nil {
		t.listener.Close()
	}
	t.wg.Wait()
	return nil
}

func (t *OracleTrap) handle(ctx context.Context, conn net.Conn) {
	defer t.wg.Done()
	defer conn.Close()

	host, port := ParseAddr(conn.RemoteAddr().String())
	_, destPort := ParseAddr(conn.LocalAddr().String())
	sess := NewSession("oracle", "tcp", host, port, destPort, t.logger)

	if !t.limiter.Acquire(host) {
		LogRejected(t.logger, "oracle", "tcp", destPort, host, "rate_limit")
		return
	}
	defer t.limiter.Release(host)

	sess.LogConnect()
	sess.RecordStart(t.metrics)
	defer sess.RecordEnd(t.metrics)
	defer sess.LogDisconnect()

	_ = conn.SetDeadline(deadlineFromContext(ctx, t.cfg.SessionTimeout))

	setOutcomeFromErr := func(err error) {
		if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() {
			sess.SetOutcome("timeout")
		} else {
			sess.SetOutcome("error")
		}
	}

	pktType, payload, err := readTNSPacket(conn)
	if err != nil {
		setOutcomeFromErr(err)
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
		setOutcomeFromErr(err)
		return
	}

	sess.LogAuthAttempt(
		slog.String("username", username),
		slog.String("service_name", serviceName),
	)
	sess.RecordCredentials(t.metrics)
	t.alerter.Alert(ctx, host, "oracle", map[string]string{"username": username, "service_name": serviceName})

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
