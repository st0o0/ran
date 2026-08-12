package trap

import (
	"context"
	"fmt"
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
	DestPort int
	Start    time.Time
	Logger   *slog.Logger

	authAttempts int
	commands     int
	payloads     int
}

func NewSession(protocol, sourceIP string, port, destPort int, logger *slog.Logger) *Session {
	s := &Session{
		ID:       uuid.NewString(),
		Protocol: protocol,
		SourceIP: sourceIP,
		Port:     port,
		DestPort: destPort,
		Start:    time.Now(),
	}
	s.Logger = logger.With(
		"protocol", protocol,
		"session_id", s.ID,
		"source_ip", sourceIP,
		"source_port", port,
		"dest_port", destPort,
	)
	return s
}

func (s *Session) addr() string {
	return net.JoinHostPort(s.SourceIP, strconv.Itoa(s.Port))
}

func (s *Session) LogConnect() {
	s.Logger.Debug(
		fmt.Sprintf("%s connect from %s", s.Protocol, s.addr()),
		"action", "connect",
	)
}

func (s *Session) LogAuthAttempt(attrs ...slog.Attr) {
	s.authAttempts++
	msg := fmt.Sprintf("%s auth from %s", s.Protocol, s.addr())
	for _, a := range attrs {
		if a.Key == "username" {
			msg += fmt.Sprintf(" user=%s", a.Value.String())
			break
		}
	}
	args := make([]any, 0, 1+len(attrs))
	args = append(args, slog.String("action", "auth_attempt"))
	for _, a := range attrs {
		args = append(args, a)
	}
	s.Logger.Info(msg, args...)
}

func (s *Session) LogCommand(command string, attrs ...slog.Attr) {
	s.commands++
	msg := fmt.Sprintf("%s command from %s cmd=%s", s.Protocol, s.addr(), command)
	args := make([]any, 0, 2+len(attrs))
	args = append(args, slog.String("action", "command"))
	args = append(args, slog.String("command", command))
	for _, a := range attrs {
		args = append(args, a)
	}
	s.Logger.Info(msg, args...)
}

func (s *Session) LogPayload(payloadType string, attrs ...slog.Attr) {
	s.payloads++
	msg := fmt.Sprintf("%s payload from %s type=%s", s.Protocol, s.addr(), payloadType)
	args := make([]any, 0, 2+len(attrs))
	args = append(args, slog.String("action", "payload"))
	args = append(args, slog.String("payload_type", payloadType))
	for _, a := range attrs {
		args = append(args, a)
	}
	s.Logger.Info(msg, args...)
}

func (s *Session) LogDisconnect() {
	dur := time.Since(s.Start)
	s.Logger.Info(
		fmt.Sprintf("%s disconnect from %s duration=%dms auth=%d cmd=%d",
			s.Protocol, s.addr(), dur.Milliseconds(), s.authAttempts, s.commands),
		"action", "disconnect",
		"duration_ms", dur.Milliseconds(),
		"auth_attempts", s.authAttempts,
		"commands", s.commands,
		"payloads", s.payloads,
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

func ListenTCP(ctx context.Context, addr string, proxyProto bool) (net.Listener, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if proxyProto {
		return &proxyListener{Listener: ln}, nil
	}
	return ln, nil
}

func deadlineFromContext(ctx context.Context, timeout time.Duration) time.Time {
	if dl, ok := ctx.Deadline(); ok && dl.Before(time.Now().Add(timeout)) {
		return dl
	}
	return time.Now().Add(timeout)
}
