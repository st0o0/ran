package trap

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

type dnsHandler struct {
	logger  *slog.Logger
	alerter alert.Alerter
}

func NewDNS(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) *UDPTrap {
	handler := &dnsHandler{
		logger:  logger,
		alerter: alerter,
	}
	return NewUDP("dns", cfg.TrapAddr("dns"), logger, m, limiter, alerter, handler)
}

func (h *dnsHandler) HandlePacket(ctx context.Context, src net.Addr, data []byte, respond func([]byte)) {
	if len(data) < 12 {
		return
	}

	id := binary.BigEndian.Uint16(data[0:2])
	qdcount := binary.BigEndian.Uint16(data[4:6])

	if qdcount == 0 {
		return
	}

	domain, qEnd, ok := parseDNSName(data, 12)
	if !ok || qEnd+4 > len(data) {
		return
	}

	qtype := binary.BigEndian.Uint16(data[qEnd : qEnd+2])
	qtypeStr := dnsTypeName(qtype)

	host, port := ParseAddr(src.String())
	sess := NewSession("dns", host, port)
	sess.LogPayload(h.logger, "dns_query", slog.String("domain", domain), slog.String("qtype", qtypeStr))
	h.alerter.Alert(ctx, host, "dns")

	questionLen := qEnd + 4 - 12
	resp := make([]byte, 12+questionLen)
	binary.BigEndian.PutUint16(resp[0:2], id)
	binary.BigEndian.PutUint16(resp[2:4], 0x8005)
	binary.BigEndian.PutUint16(resp[4:6], 1)
	copy(resp[12:], data[12:qEnd+4])

	respond(resp)
}

func parseDNSName(data []byte, offset int) (string, int, bool) {
	var labels []string
	pos := offset
	for {
		if pos >= len(data) {
			return "", 0, false
		}
		length := int(data[pos])
		pos++
		if length == 0 {
			break
		}
		if pos+length > len(data) {
			return "", 0, false
		}
		labels = append(labels, string(data[pos:pos+length]))
		pos += length
	}
	return joinLabels(labels), pos, true
}

func joinLabels(labels []string) string {
	if len(labels) == 0 {
		return ""
	}
	result := labels[0]
	for _, l := range labels[1:] {
		result += "." + l
	}
	return result
}

func dnsTypeName(qtype uint16) string {
	switch qtype {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 255:
		return "ANY"
	default:
		return fmt.Sprintf("%d", qtype)
	}
}
