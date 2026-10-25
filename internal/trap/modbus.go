package trap

import (
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
		switch modbusKindOf(fc) {
		case modbusRead:
			// Reads and device identification are fingerprinting: they log but do
			// not count as payload, so a read-only session stays a probe.
			sess.Log("modbus_request", attrs...)
		default:
			sess.LogPayload("modbus_request", attrs...)
			meta := modbusAlertMeta(attrs)
			meta["kind"] = "write"
			if modbusKindOf(fc) == modbusUnknown {
				meta["kind"] = "unknown_function"
			}
			sess.Alert(ctx, meta)
		}

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

type modbusKind int

const (
	// modbusRead covers the read function codes and device identification.
	modbusRead modbusKind = iota
	// modbusWrite covers the write function codes.
	modbusWrite
	// modbusUnknown is every other function code.
	modbusUnknown
)

// modbusKindOf classifies a function code: 1-4 (read coils, discrete inputs,
// holding and input registers) and 43 (device identification) are read-only
// fingerprinting; 5, 6, 15, 16, 22 and 23 write (23 also reads, but writes).
// Everything else is unknown and treated like a write.
func modbusKindOf(fc byte) modbusKind {
	switch fc {
	case 1, 2, 3, 4, 43:
		return modbusRead
	case 5, 6, 15, 16, 22, 23:
		return modbusWrite
	default:
		return modbusUnknown
	}
}

// Maximum quantities allowed by the Modbus specification. Declared quantities
// above them are logged cut to the maximum.
const (
	modbusMaxReadBits   = 2000 // FC 1, 2
	modbusMaxReadRegs   = 125  // FC 3, 4, read part of FC 23
	modbusMaxWriteBits  = 1968 // FC 15
	modbusMaxWriteRegs  = 123  // FC 16
	modbusMaxWriteRegs2 = 121  // write part of FC 23
)

func capQuantity(qty uint16, limit int) int {
	return min(int(qty), limit)
}

// parseModbusPDU extracts the function code and the addresses, quantities and
// values of the requests it knows. Every field is read with a length check and
// quantities are capped; nothing is allocated from the declared quantity.
func parseModbusPDU(fc byte, data []byte) []slog.Attr {
	attrs := []slog.Attr{
		slog.Int("function_code", int(fc)),
	}
	u16 := func(off int) int { return int(binary.BigEndian.Uint16(data[off : off+2])) }

	switch {
	case (fc == 1 || fc == 2) && len(data) >= 4:
		attrs = append(attrs,
			slog.Int("starting_address", u16(0)),
			slog.Int("quantity", capQuantity(binary.BigEndian.Uint16(data[2:4]), modbusMaxReadBits)),
		)
	case (fc == 3 || fc == 4) && len(data) >= 4:
		attrs = append(attrs,
			slog.Int("starting_address", u16(0)),
			slog.Int("quantity", capQuantity(binary.BigEndian.Uint16(data[2:4]), modbusMaxReadRegs)),
		)
	case (fc == 5 || fc == 6) && len(data) >= 4:
		attrs = append(attrs,
			slog.Int("address", u16(0)),
			slog.Int("value", u16(2)),
		)
	case fc == 15 && len(data) >= 4:
		attrs = append(attrs,
			slog.Int("address", u16(0)),
			slog.Int("quantity", capQuantity(binary.BigEndian.Uint16(data[2:4]), modbusMaxWriteBits)),
		)
	case fc == 16 && len(data) >= 4:
		attrs = append(attrs,
			slog.Int("address", u16(0)),
			slog.Int("quantity", capQuantity(binary.BigEndian.Uint16(data[2:4]), modbusMaxWriteRegs)),
		)
	case fc == 22 && len(data) >= 6:
		attrs = append(attrs,
			slog.Int("address", u16(0)),
			slog.Int("and_mask", u16(2)),
			slog.Int("or_mask", u16(4)),
		)
	case fc == 23 && len(data) >= 8:
		attrs = append(attrs,
			slog.Int("starting_address", u16(0)),
			slog.Int("quantity", capQuantity(binary.BigEndian.Uint16(data[2:4]), modbusMaxReadRegs)),
			slog.Int("address", u16(4)),
			slog.Int("write_quantity", capQuantity(binary.BigEndian.Uint16(data[6:8]), modbusMaxWriteRegs2)),
		)
	case fc == 43 && len(data) >= 1:
		attrs = append(attrs, slog.Int("mei_type", int(data[0])))
	}

	return attrs
}

// modbusAlertMeta turns the numeric request attributes into alert meta. The
// values are small decimal numbers, so the meta is bounded by construction.
func modbusAlertMeta(attrs []slog.Attr) map[string]string {
	meta := make(map[string]string, len(attrs))
	for _, a := range attrs {
		meta[a.Key] = strconv.FormatInt(a.Value.Int64(), 10)
	}
	return meta
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
