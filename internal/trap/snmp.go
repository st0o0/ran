package trap

import (
	"context"
	"fmt"
	"log/slog"

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
	return NewUDP("snmp", cfg.TrapAddrs("snmp"), logger, m, limiter, alerter, handler)
}

func (h *snmpHandler) HandlePacket(ctx context.Context, sess *Session, data []byte, respond func([]byte)) {
	tag, _, value, _, ok := readTLV(data, 0)
	if !ok || tag != 0x30 {
		sess.LogError("parse_failed", fmt.Errorf("invalid SNMP sequence tag"))
		return
	}
	seq := value

	tag, _, value, next, ok := readTLV(seq, 0)
	if !ok || tag != 0x02 || len(value) == 0 {
		sess.LogError("parse_failed", fmt.Errorf("invalid SNMP version field"))
		return
	}
	version := value[0]
	if version >= 3 {
		sess.LogError("parse_failed", fmt.Errorf("unsupported SNMP version: %d", version))
		return
	}

	tag, _, value, next, ok = readTLV(seq, next)
	if !ok || tag != 0x04 {
		sess.LogError("parse_failed", fmt.Errorf("invalid SNMP community field"))
		return
	}
	community := string(value)

	tag, _, value, _, ok = readTLV(seq, next)
	if !ok || (tag != 0xA0 && tag != 0xA1) {
		sess.LogError("parse_failed", fmt.Errorf("invalid SNMP PDU tag: 0x%02x", tag))
		return
	}
	pdu := value

	sess.LogPayload("snmp_request", slog.String("community", community), slog.Int("version", int(version)))
	h.alerter.Alert(ctx, sess.SourceIP, "snmp", map[string]string{"community": community})

	reqTag, _, reqIDValue, _, ok := readTLV(pdu, 0)
	if !ok || reqTag != 0x02 {
		return
	}

	varbindList := berSequence(0x30)
	errorIndex := berInteger(0x02, 0)
	errorStatus := berInteger(0x02, 2)
	requestID := append([]byte{0x02}, berLength(len(reqIDValue))...)
	requestID = append(requestID, reqIDValue...)

	pduContents := make([]byte, 0, len(requestID)+len(errorStatus)+len(errorIndex)+len(varbindList))
	pduContents = append(pduContents, requestID...)
	pduContents = append(pduContents, errorStatus...)
	pduContents = append(pduContents, errorIndex...)
	pduContents = append(pduContents, varbindList...)

	getResponse := append([]byte{0xA2}, berLength(len(pduContents))...)
	getResponse = append(getResponse, pduContents...)

	communityBytes := berOctetString(0x04, []byte(community))
	versionBytes := berInteger(0x02, int64(version))

	outer := make([]byte, 0, len(versionBytes)+len(communityBytes)+len(getResponse))
	outer = append(outer, versionBytes...)
	outer = append(outer, communityBytes...)
	outer = append(outer, getResponse...)

	response := berSequence(0x30, outer)
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

