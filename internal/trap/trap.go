package trap

import (
	"context"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/st0o0/ran/internal/metrics"
)

type Trap interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

type Session struct {
	ID        string
	Protocol  string
	Transport string
	SourceIP  string
	Port      int
	DestPort  int
	Start     time.Time
	Logger    *slog.Logger
	Outcome   string

	authAttempts int
	commands     int
	payloads     int
}

func (s *Session) SetOutcome(outcome string) {
	s.Outcome = outcome
}

func NewSession(protocol, transport, sourceIP string, port, destPort int, logger *slog.Logger) *Session {
	s := &Session{
		ID:        uuid.NewString(),
		Protocol:  protocol,
		Transport: transport,
		SourceIP:  sourceIP,
		Port:      port,
		DestPort:  destPort,
		Start:     time.Now(),
		Outcome:   "completed",
	}
	s.Logger = logger.With(
		"protocol", protocol,
		"transport", transport,
		"session_id", s.ID,
		"source_ip", sourceIP,
		"source_port", port,
		"dest_port", destPort,
	)
	return s
}

func (s *Session) LogConnect() {
	s.Logger.Info("session started", "action", "connect")
}

func (s *Session) LogAuthAttempt(attrs ...slog.Attr) {
	s.authAttempts++
	args := make([]any, 0, 1+len(attrs))
	args = append(args, slog.String("action", "auth_attempt"))
	for _, a := range attrs {
		args = append(args, a)
	}
	s.Logger.Info("credentials captured", args...)
}

func (s *Session) LogCommand(command string, attrs ...slog.Attr) {
	s.commands++
	args := make([]any, 0, 2+len(attrs))
	args = append(args, slog.String("action", "command"))
	args = append(args, slog.String("command", command))
	for _, a := range attrs {
		args = append(args, a)
	}
	s.Logger.Info("command received", args...)
}

func (s *Session) LogPayload(payloadType string, attrs ...slog.Attr) {
	s.payloads++
	args := make([]any, 0, 2+len(attrs))
	args = append(args, slog.String("action", "payload"))
	args = append(args, slog.String("payload_type", payloadType))
	for _, a := range attrs {
		args = append(args, a)
	}
	s.Logger.Info("payload received", args...)
}

func (s *Session) LogDisconnect() {
	dur := time.Since(s.Start)
	s.Logger.Info("session ended",
		"action", "disconnect",
		"outcome", s.Outcome,
		"duration_ms", dur.Milliseconds(),
		"auth_attempts", s.authAttempts,
		"commands", s.commands,
		"payloads", s.payloads,
	)
}

func LogRejected(logger *slog.Logger, protocol, transport string, destPort int, sourceIP, reason string) {
	logger.Warn("connection rejected",
		"action", "rejected",
		"protocol", protocol,
		"transport", transport,
		"dest_port", destPort,
		"source_ip", sourceIP,
		"reason", reason,
	)
}

func (s *Session) LogError(errorType string, err error) {
	s.Logger.Error("internal error",
		"action", "error",
		"error_type", errorType,
		"error", err.Error(),
	)
}

func LogErrorStandalone(logger *slog.Logger, protocol, errorType string, err error) {
	logger.Error("internal error",
		"action", "error",
		"protocol", protocol,
		"error_type", errorType,
		"error", err.Error(),
	)
}

func (s *Session) RecordStart(m *metrics.Metrics) {
	m.ActiveSessions.WithLabelValues(s.Protocol).Inc()
}

func (s *Session) RecordEnd(m *metrics.Metrics) {
	m.ActiveSessions.WithLabelValues(s.Protocol).Dec()
	m.Connections.WithLabelValues(s.Protocol, s.Outcome).Inc()
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

type contextKey string

var destPortCtxKey = contextKey("destPort")

func ConnContextWithDestPort(ctx context.Context, conn net.Conn) context.Context {
	_, port := ParseAddr(conn.LocalAddr().String())
	return context.WithValue(ctx, destPortCtxKey, port)
}

func DestPortFromContext(ctx context.Context) int {
	if v, ok := ctx.Value(destPortCtxKey).(int); ok {
		return v
	}
	return 0
}

type MultiListener struct {
	listeners []net.Listener
	connCh    chan net.Conn
	done      chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
}

func (ml *MultiListener) Accept() (net.Conn, error) {
	conn, ok := <-ml.connCh
	if !ok {
		return nil, net.ErrClosed
	}
	return conn, nil
}

func (ml *MultiListener) Close() error {
	ml.closeOnce.Do(func() {
		close(ml.done)
		for _, ln := range ml.listeners {
			ln.Close()
		}
		ml.wg.Wait()
		close(ml.connCh)
	})
	return nil
}

func (ml *MultiListener) Addr() net.Addr {
	return ml.listeners[0].Addr()
}

func ListenMultiTCP(ctx context.Context, addrs []string, proxyProto bool) (*MultiListener, error) {
	var lc net.ListenConfig
	listeners := make([]net.Listener, 0, len(addrs))
	for _, addr := range addrs {
		ln, err := lc.Listen(ctx, "tcp", addr)
		if err != nil {
			for _, prev := range listeners {
				prev.Close()
			}
			return nil, err
		}
		if proxyProto {
			ln = &proxyListener{Listener: ln}
		}
		listeners = append(listeners, ln)
	}

	ml := &MultiListener{
		listeners: listeners,
		connCh:    make(chan net.Conn, 64),
		done:      make(chan struct{}),
	}

	for _, ln := range listeners {
		ml.wg.Add(1)
		go func(l net.Listener) {
			defer ml.wg.Done()
			for {
				conn, err := l.Accept()
				if err != nil {
					return
				}
				select {
				case ml.connCh <- conn:
				case <-ml.done:
					conn.Close()
					return
				}
			}
		}(ln)
	}

	return ml, nil
}

func authSleep(ctx context.Context, baseDelay time.Duration, attempt int) error {
	if baseDelay <= 0 {
		return nil
	}
	multiplier := 1 << attempt
	if multiplier > 4 {
		multiplier = 4
	}
	delay := baseDelay * time.Duration(multiplier)
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func deadlineFromContext(ctx context.Context, timeout time.Duration) time.Time {
	if dl, ok := ctx.Deadline(); ok && dl.Before(time.Now().Add(timeout)) {
		return dl
	}
	return time.Now().Add(timeout)
}
