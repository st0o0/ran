package trap

import (
	"context"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/st0o0/ran/internal/metrics"
)

type Trap interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

type Session struct {
	ID       string
	Protocol string
	SourceIP string
	Port     int
	Start    time.Time
}

func NewSession(protocol, sourceIP string, port int) *Session {
	return &Session{
		ID:       uuid.NewString(),
		Protocol: protocol,
		SourceIP: sourceIP,
		Port:     port,
		Start:    time.Now(),
	}
}

func (s *Session) LogConnect(logger *slog.Logger) {
	logger.Info("connect",
		"protocol", s.Protocol,
		"session_id", s.ID,
		"source_ip", s.SourceIP,
		"source_port", s.Port,
		"action", "connect",
	)
}

func (s *Session) LogAuthAttempt(logger *slog.Logger, attrs ...slog.Attr) {
	base := []slog.Attr{
		slog.String("protocol", s.Protocol),
		slog.String("session_id", s.ID),
		slog.String("source_ip", s.SourceIP),
		slog.Int("source_port", s.Port),
		slog.String("action", "auth_attempt"),
	}
	args := make([]any, 0, len(base)+len(attrs))
	for _, a := range append(base, attrs...) {
		args = append(args, a)
	}
	logger.Info("auth_attempt", args...)
}

func (s *Session) LogCommand(logger *slog.Logger, command string, attrs ...slog.Attr) {
	base := []slog.Attr{
		slog.String("protocol", s.Protocol),
		slog.String("session_id", s.ID),
		slog.String("source_ip", s.SourceIP),
		slog.Int("source_port", s.Port),
		slog.String("action", "command"),
		slog.String("command", command),
	}
	args := make([]any, 0, len(base)+len(attrs))
	for _, a := range append(base, attrs...) {
		args = append(args, a)
	}
	logger.Info("command", args...)
}

func (s *Session) LogPayload(logger *slog.Logger, payloadType string, attrs ...slog.Attr) {
	base := []slog.Attr{
		slog.String("protocol", s.Protocol),
		slog.String("session_id", s.ID),
		slog.String("source_ip", s.SourceIP),
		slog.Int("source_port", s.Port),
		slog.String("action", "payload"),
		slog.String("payload_type", payloadType),
	}
	args := make([]any, 0, len(base)+len(attrs))
	for _, a := range append(base, attrs...) {
		args = append(args, a)
	}
	logger.Info("payload", args...)
}

func (s *Session) LogDisconnect(logger *slog.Logger) {
	logger.Info("disconnect",
		"protocol", s.Protocol,
		"session_id", s.ID,
		"source_ip", s.SourceIP,
		"source_port", s.Port,
		"action", "disconnect",
	)
}

func (s *Session) RecordStart(m *metrics.Metrics) {
	m.Connections.WithLabelValues(s.Protocol).Inc()
	m.ActiveSessions.WithLabelValues(s.Protocol).Inc()
}

func (s *Session) RecordEnd(m *metrics.Metrics) {
	m.ActiveSessions.WithLabelValues(s.Protocol).Dec()
	m.SessionDuration.WithLabelValues(s.Protocol).Observe(time.Since(s.Start).Seconds())
}

func (s *Session) RecordCredentials(m *metrics.Metrics) {
	m.CredentialsCaptured.WithLabelValues(s.Protocol).Inc()
}

func ParseAddr(addr string) (string, int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}

func deadlineFromContext(ctx context.Context, timeout time.Duration) time.Time {
	if dl, ok := ctx.Deadline(); ok && dl.Before(time.Now().Add(timeout)) {
		return dl
	}
	return time.Now().Add(timeout)
}
