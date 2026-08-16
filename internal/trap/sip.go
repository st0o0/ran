package trap

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

type sipHandler struct {
	logger   *slog.Logger
	destPort int
	alerter  alert.Alerter
}

func NewSIP(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) *UDPTrap {
	_, destPort := ParseAddr(cfg.TrapAddr("sip"))
	handler := &sipHandler{
		logger:   logger,
		destPort: destPort,
		alerter:  alerter,
	}
	return NewUDP("sip", cfg.TrapAddr("sip"), logger, m, limiter, alerter, handler)
}

func (h *sipHandler) HandlePacket(ctx context.Context, src net.Addr, data []byte, respond func([]byte)) {
	msg := string(data)
	var lines []string
	if strings.Contains(msg, "\r\n") {
		lines = strings.Split(msg, "\r\n")
	} else {
		lines = strings.Split(msg, "\n")
	}

	if len(lines) == 0 {
		return
	}

	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) < 3 {
		return
	}
	method := parts[0]

	headers := make(map[string]string)
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		idx := strings.Index(line, ": ")
		if idx < 0 {
			continue
		}
		key := strings.ToLower(line[:idx])
		value := line[idx+2:]
		headers[key] = value
	}

	from := headers["from"]
	to := headers["to"]
	via := headers["via"]
	callID := headers["call-id"]
	authorization := headers["authorization"]

	host, port := ParseAddr(src.String())
	sess := NewSession("sip", host, port, h.destPort, h.logger)
	sess.LogPayload("sip_request", slog.String("method", method), slog.String("from", from), slog.String("to", to))

	if authorization != "" {
		if username := extractSIPUsername(authorization); username != "" {
			sess.LogPayload("auth_attempt", slog.String("username", username))
		}
	}

	h.alerter.Alert(ctx, host, "sip", map[string]string{"method": method, "from": from, "to": to})

	nonce := generateNonce()
	response := fmt.Sprintf("SIP/2.0 401 Unauthorized\r\nVia: %s\r\nFrom: %s\r\nTo: %s\r\nCall-ID: %s\r\nWWW-Authenticate: Digest realm=\"ran\",nonce=\"%s\"\r\nContent-Length: 0\r\n\r\n",
		via, from, to, callID, nonce)

	respond([]byte(response))
}

func extractSIPUsername(auth string) string {
	const key = "username=\""
	idx := strings.Index(auth, key)
	if idx < 0 {
		return ""
	}
	start := idx + len(key)
	end := strings.Index(auth[start:], "\"")
	if end < 0 {
		return ""
	}
	return auth[start : start+end]
}

func generateNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "deadbeef"
	}
	return hex.EncodeToString(b)
}
