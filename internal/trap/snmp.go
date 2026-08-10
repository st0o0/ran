package trap

import (
	"context"
	"log/slog"
	"net"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

type snmpHandler struct {
	logger  *slog.Logger
	alerter alert.Alerter
}

func NewSNMP(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) *UDPTrap {
	handler := &snmpHandler{
		logger:  logger,
		alerter: alerter,
	}
	return NewUDP("snmp", cfg.TrapAddr("snmp"), logger, m, limiter, alerter, handler)
}

func (h *snmpHandler) HandlePacket(ctx context.Context, src net.Addr, data []byte, respond func([]byte)) {
	tag, _, value, _, ok := readTLV(data, 0)
	if !ok || tag != 0x30 {
		return
	}
	seq := value

	tag, _, value, next, ok := readTLV(seq, 0)
	if !ok || tag != 0x02 || len(value) == 0 {
		return
	}
	version := value[0]
	if version >= 3 {
		return
	}

	tag, _, value, next, ok = readTLV(seq, next)
	if !ok || tag != 0x04 {
		return
	}
	community := string(value)

	tag, _, value, _, ok = readTLV(seq, next)
	if !ok || (tag != 0xA0 && tag != 0xA1) {
		return
	}
	pdu := value

	host, port := ParseAddr(src.String())
	sess := NewSession("snmp", host, port)
	sess.LogPayload(h.logger, "snmp_request", slog.String("community", community), slog.Int("version", int(version)))
	h.alerter.Alert(ctx, host, "snmp")

	reqTag, _, reqIDValue, _, ok := readTLV(pdu, 0)
	if !ok || reqTag != 0x02 {
		return
	}

	varbindList := berSequence(nil)
	errorIndex := berInteger(0)
	errorStatus := berInteger(2)
	requestID := append([]byte{0x02}, berLength(len(reqIDValue))...)
	requestID = append(requestID, reqIDValue...)

	pduContents := make([]byte, 0, len(requestID)+len(errorStatus)+len(errorIndex)+len(varbindList))
	pduContents = append(pduContents, requestID...)
	pduContents = append(pduContents, errorStatus...)
	pduContents = append(pduContents, errorIndex...)
	pduContents = append(pduContents, varbindList...)

	getResponse := append([]byte{0xA2}, berLength(len(pduContents))...)
	getResponse = append(getResponse, pduContents...)

	communityBytes := berOctetString([]byte(community))
	versionBytes := berInteger(int(version))

	outer := make([]byte, 0, len(versionBytes)+len(communityBytes)+len(getResponse))
	outer = append(outer, versionBytes...)
	outer = append(outer, communityBytes...)
	outer = append(outer, getResponse...)

	response := berSequence(outer)
	respond(response)
}

func readTLV(data []byte, offset int) (tag byte, length int, value []byte, next int, ok bool) {
	if offset >= len(data) {
		return 0, 0, nil, 0, false
	}
	tag = data[offset]
	offset++

	if offset >= len(data) {
		return 0, 0, nil, 0, false
	}
	b := data[offset]
	offset++

	switch {
	case b < 0x80:
		length = int(b)
	case b == 0x81:
		if offset >= len(data) {
			return 0, 0, nil, 0, false
		}
		length = int(data[offset])
		offset++
	case b == 0x82:
		if offset+1 >= len(data) {
			return 0, 0, nil, 0, false
		}
		length = int(data[offset])<<8 | int(data[offset+1])
		offset += 2
	default:
		return 0, 0, nil, 0, false
	}

	if offset+length > len(data) {
		return 0, 0, nil, 0, false
	}
	value = data[offset : offset+length]
	next = offset + length
	return tag, length, value, next, true
}

func berLength(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}
	if length <= 0xFF {
		return []byte{0x81, byte(length)}
	}
	return []byte{0x82, byte(length >> 8), byte(length)}
}

func berInteger(value int) []byte {
	var b []byte
	if value == 0 {
		b = []byte{0}
	} else {
		v := value
		var tmp []byte
		for v > 0 {
			tmp = append([]byte{byte(v & 0xFF)}, tmp...)
			v >>= 8
		}
		if tmp[0]&0x80 != 0 {
			tmp = append([]byte{0}, tmp...)
		}
		b = tmp
	}
	result := []byte{0x02}
	result = append(result, berLength(len(b))...)
	result = append(result, b...)
	return result
}

func berOctetString(value []byte) []byte {
	result := []byte{0x04}
	result = append(result, berLength(len(value))...)
	result = append(result, value...)
	return result
}

func berSequence(contents []byte) []byte {
	result := []byte{0x30}
	result = append(result, berLength(len(contents))...)
	result = append(result, contents...)
	return result
}
