package trap

import (
	"context"
	"log/slog"
	"net"
	"strconv"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

type ntpHandler struct {
	logger   *slog.Logger
	destPort int
	alerter  alert.Alerter
}

func NewNTP(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) *UDPTrap {
	_, destPort := ParseAddr(cfg.TrapAddr("ntp"))
	handler := &ntpHandler{
		logger:   logger,
		destPort: destPort,
		alerter:  alerter,
	}
	return NewUDP("ntp", cfg.TrapAddr("ntp"), logger, m, limiter, alerter, handler)
}

func (h *ntpHandler) HandlePacket(ctx context.Context, src net.Addr, data []byte, respond func([]byte)) {
	if len(data) < 48 {
		return
	}

	version := int((data[0] >> 3) & 0x07)
	mode := int(data[0] & 0x07)

	if mode == 7 {
		return
	}

	if mode != 3 {
		return
	}

	host, port := ParseAddr(src.String())
	sess := NewSession("ntp", host, port, h.destPort, h.logger)
	sess.LogPayload("ntp_request", slog.Int("version", version), slog.Int("mode", mode))
	h.alerter.Alert(ctx, host, "ntp", map[string]string{"version": strconv.Itoa(version), "mode": strconv.Itoa(mode)})

	resp := make([]byte, 48)
	resp[0] = byte((3 << 6) | (version << 3) | 4)
	resp[1] = 0
	resp[2] = 0
	resp[3] = 0
	resp[12] = 0x44 // D
	resp[13] = 0x45 // E
	resp[14] = 0x4E // N
	resp[15] = 0x59 // Y
	copy(resp[24:32], data[40:48])

	respond(resp)
}
