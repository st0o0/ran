package trap

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

type ModbusTrap struct {
	cfg      *config.Config
	logger   *slog.Logger
	metrics  *metrics.Metrics
	limiter  *Limiter
	alerter  alert.Alerter
	listener net.Listener
	wg       sync.WaitGroup
}

func NewModbus(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) *ModbusTrap {
	return &ModbusTrap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
		limiter: limiter,
		alerter: alerter,
	}
}

func (t *ModbusTrap) Start(ctx context.Context) error {
	ln, err := ListenTCP(ctx, t.cfg.TrapAddr("modbus"), t.cfg.ProxyProtocol)
	if err != nil {
		return fmt.Errorf("modbus listen: %w", err)
	}
	t.listener = ln
	t.logger.Info("listening", "addr", t.cfg.TrapAddr("modbus"))

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
			t.logger.Debug("accept error", "error", err)
			continue
		}
		t.wg.Add(1)
		go t.handle(ctx, conn)
	}
	return nil
}

func (t *ModbusTrap) Stop(_ context.Context) error {
	if t.listener != nil {
		t.listener.Close()
	}
	t.wg.Wait()
	return nil
}

func (t *ModbusTrap) handle(ctx context.Context, conn net.Conn) {
	defer t.wg.Done()
	defer conn.Close()

	host, port := ParseAddr(conn.RemoteAddr().String())
	_, destPort := ParseAddr(t.listener.Addr().String())
	sess := NewSession("modbus", host, port, destPort, t.logger)

	if !t.limiter.Acquire(host) {
		t.logger.Warn("connection rejected", "source_ip", host, "reason", "limit_exceeded")
		return
	}
	defer t.limiter.Release(host)

	sess.LogConnect()
	sess.RecordStart(t.metrics)
	defer sess.RecordEnd(t.metrics)
	defer sess.LogDisconnect()

	_ = conn.SetDeadline(deadlineFromContext(ctx, t.cfg.SessionTimeout))

	for {
		transactionID, unitID, fc, pduData, err := readModbusRequest(conn)
		if err != nil {
			return
		}

		attrs := parseModbusPDU(fc, pduData)
		sess.LogPayload("modbus_request", attrs...)
		t.alerter.Alert(ctx, host, "modbus", map[string]string{"function_code": fmt.Sprintf("%d", fc)})

		resp := buildModbusException(transactionID, unitID, fc, 0x01)
		if _, err := conn.Write(resp); err != nil {
			return
		}
	}
}

func readModbusRequest(r io.Reader) (transactionID uint16, unitID byte, fc byte, pduData []byte, err error) {
	header := make([]byte, 7)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, 0, 0, nil, err
	}

	transactionID = binary.BigEndian.Uint16(header[0:2])
	protocolID := binary.BigEndian.Uint16(header[2:4])
	length := binary.BigEndian.Uint16(header[4:6])
	unitID = header[6]

	if protocolID != 0 {
		return 0, 0, 0, nil, fmt.Errorf("invalid protocol ID: %d", protocolID)
	}
	if length < 1 || length > 255 {
		return 0, 0, 0, nil, fmt.Errorf("invalid length: %d", length)
	}

	pdu := make([]byte, length-1)
	if _, err := io.ReadFull(r, pdu); err != nil {
		return 0, 0, 0, nil, err
	}
	if len(pdu) == 0 {
		return 0, 0, 0, nil, fmt.Errorf("empty PDU")
	}

	fc = pdu[0]
	pduData = pdu[1:]
	return transactionID, unitID, fc, pduData, nil
}

func parseModbusPDU(fc byte, data []byte) []slog.Attr {
	attrs := []slog.Attr{
		slog.Int("function_code", int(fc)),
	}

	switch {
	case fc >= 1 && fc <= 4 && len(data) >= 4:
		addr := binary.BigEndian.Uint16(data[0:2])
		qty := binary.BigEndian.Uint16(data[2:4])
		attrs = append(attrs,
			slog.Int("starting_address", int(addr)),
			slog.Int("quantity", int(qty)),
		)
	case (fc == 5 || fc == 6) && len(data) >= 4:
		addr := binary.BigEndian.Uint16(data[0:2])
		value := binary.BigEndian.Uint16(data[2:4])
		attrs = append(attrs,
			slog.Int("address", int(addr)),
			slog.Int("value", int(value)),
		)
	case (fc == 15 || fc == 16) && len(data) >= 4:
		addr := binary.BigEndian.Uint16(data[0:2])
		qty := binary.BigEndian.Uint16(data[2:4])
		attrs = append(attrs,
			slog.Int("address", int(addr)),
			slog.Int("quantity", int(qty)),
		)
	}

	return attrs
}

func buildModbusException(transactionID uint16, unitID byte, fc byte, exceptionCode byte) []byte {
	resp := make([]byte, 9)
	binary.BigEndian.PutUint16(resp[0:2], transactionID)
	binary.BigEndian.PutUint16(resp[2:4], 0) // protocol ID
	binary.BigEndian.PutUint16(resp[4:6], 3) // length: unit ID + exception FC + exception code
	resp[6] = unitID
	resp[7] = fc | 0x80
	resp[8] = exceptionCode
	return resp
}
