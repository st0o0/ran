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

type ModbusTrap struct {
	*tcpServer
	cfg     *config.Config
	logger  *slog.Logger
	metrics *metrics.Metrics
}

func NewModbus(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter Reporter) *ModbusTrap {
	t := &ModbusTrap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
	}
	t.tcpServer = newTCPServer("modbus", cfg, logger, m, limiter, alerter, t.handle)
	return t
}

func (t *ModbusTrap) handle(ctx context.Context, conn net.Conn, sess *Session) {
	for {
		transactionID, unitID, fc, pduData, err := readModbusRequest(conn)
		if err != nil {
			setOutcome(sess, err)
			return
		}

		attrs := parseModbusPDU(fc, pduData)
		sess.LogPayload("modbus_request", attrs...)
		sess.Alert(ctx, map[string]string{"function_code": fmt.Sprintf("%d", fc)})

		resp := buildModbusException(transactionID, unitID, fc, 0x01)
		if _, err := conn.Write(resp); err != nil {
			setOutcome(sess, err)
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
