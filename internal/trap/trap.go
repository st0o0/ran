package trap

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/metrics"
)

// Reporter is the part of the sensor that traps use: they report activity and
// the end of a session. Lifecycle (Close) belongs to the owner, not the traps.
type Reporter interface {
	Alert(ctx context.Context, info alert.SessionInfo, meta map[string]string) alert.Class
	SessionEnd(info alert.SessionInfo) bool
}

var _ Reporter = alert.Alerter(nil)

type Trap interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

type Session struct {
	ID        string
	Protocol  string
	Transport alert.Transport
	SourceIP  string
	Port      int
	DestPort  int
	Start     time.Time
	Logger    *slog.Logger
	Outcome   string

	// Sensor classifies the session and aggregates probe log output. TCP traps
	// set it; UDP sessions leave it nil because UDP sources are spoofable.
	Sensor Reporter

	authAttempts int
	commands     int
	payloads     int
	// payloadBytes counts the bytes of attacker-supplied data captured by
	// LogPayload attributes (at least 1 per payload event).
	payloadBytes int

	alertedClass   alert.Class
	connectPending bool
	// ignored is set when the source is in RAN_IGNORE_IPS: the session is served
	// and logged with ignored=true but the sensor never records it.
	ignored bool
}

// ignoreChecker is implemented by sensors that know the ignore list.
type ignoreChecker interface{ Ignored(ip string) bool }

// UseSensor wires the sensor into the session. If the sensor reports the
// source as ignored, the session is marked so that its log lines carry
// ignored=true and RecordStart counts it.
func (s *Session) UseSensor(r Reporter) {
	s.Sensor = r
	if ic, ok := r.(ignoreChecker); ok && ic.Ignored(s.SourceIP) {
		s.markIgnored()
	}
}

func (s *Session) markIgnored() {
	s.ignored = true
	s.Logger = s.Logger.With("ignored", true)
}

// Ignored reports whether the session source is in the ignore list.
func (s *Session) Ignored() bool { return s.ignored }

// Info returns the session snapshot handed to the sensor.
func (s *Session) Info() alert.SessionInfo {
	return alert.SessionInfo{
		SourceIP:     s.SourceIP,
		Protocol:     s.Protocol,
		Transport:    s.Transport,
		DestPort:     s.DestPort,
		AuthAttempts: s.authAttempts,
		Commands:     s.commands,
		PayloadBytes: s.payloadBytes,
		AlertedClass: s.alertedClass,
	}
}

// Alert reports activity to the sensor with the session counters as they are
// now. The source IP is always the socket peer recorded in the session.
func (s *Session) Alert(ctx context.Context, meta map[string]string) {
	if s.Sensor == nil {
		return
	}
	class := s.Sensor.Alert(ctx, s.Info(), meta)
	s.alertedClass = alert.MaxClass(s.alertedClass, class)
}

func (s *Session) SetOutcome(outcome string) {
	s.Outcome = outcome
}

func NewSession(protocol string, transport alert.Transport, sourceIP string, port, destPort int, logger *slog.Logger) *Session {
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

// LogConnect logs the session start. With a sensor on a TCP session the line is
// held back: probe sessions are summarized instead, and sessions that do
// something log it right before their first event or at the end.
func (s *Session) LogConnect() {
	if s.Sensor != nil && s.Transport == alert.TransportTCP {
		s.connectPending = true
		return
	}
	s.Logger.Info("session started", "action", "connect")
}

func (s *Session) flushConnect() {
	if s.connectPending {
		s.connectPending = false
		s.Logger.Info("session started", "action", "connect")
	}
}

// Password log modes (RAN_LOG_PASSWORDS).
const (
	passwordsOff int32 = iota
	passwordsMask
	passwordsOn
)

var passwordMode atomic.Int32

// SetPasswordLogMode sets how passwords appear in credential log events:
// "off" (default, field omitted), "mask" or "on".
func SetPasswordLogMode(mode string) {
	switch mode {
	case "mask":
		passwordMode.Store(passwordsMask)
	case "on":
		passwordMode.Store(passwordsOn)
	default:
		passwordMode.Store(passwordsOff)
	}
}

// applyPasswordMode returns the attribute to log, or false if it must be omitted.
func applyPasswordMode(a slog.Attr) (slog.Attr, bool) {
	switch passwordMode.Load() {
	case passwordsOn:
		return a, true
	case passwordsMask:
		return slog.String("password", fmt.Sprintf("*** (%d)", len(a.Value.String()))), true
	default:
		return a, false
	}
}

func (s *Session) LogAuthAttempt(attrs ...slog.Attr) {
	s.authAttempts++
	s.flushConnect()
	args := make([]any, 0, 1+len(attrs))
	args = append(args, slog.String("action", "auth_attempt"))
	for _, a := range attrs {
		if a.Key == "password" {
			var ok bool
			if a, ok = applyPasswordMode(a); !ok {
				continue
			}
		}
		args = append(args, a)
	}
	s.Logger.Info("credentials captured", args...)
}

// sensitiveVerbs carry a secret in the arguments that follow them. The first group
// is only honored in the first two tokens (an IMAP tag may come first).
var sensitiveVerbs = map[string]bool{"LOGIN": true, "PASS": true, "OPER": true, "AUTHENTICATE": true}

// sensitiveMarkers hide everything after them wherever they appear (redis AUTH,
// HELLO ... AUTH, MIGRATE ... AUTH2, CONFIG SET requirepass, IRC NickServ IDENTIFY).
var sensitiveMarkers = map[string]bool{"AUTH": true, "AUTH2": true, "IDENTIFY": true, "REQUIREPASS": true, "MASTERAUTH": true, "MASTERUSER": true}

// redactCommand removes credential arguments from a raw command line according to
// the password log mode: on keeps the line, mask replaces the secret part with its
// length, off drops it.
func redactCommand(line string) string {
	if passwordMode.Load() == passwordsOn {
		return line
	}
	fields := strings.Fields(line)
	// ACL SETUSER <name> <rules...>: the rules carry the passwords (>pw, #hash).
	if len(fields) >= 4 && strings.EqualFold(fields[0], "ACL") && strings.EqualFold(fields[1], "SETUSER") {
		return redactTail(fields, 3)
	}
	for i, f := range fields {
		w := strings.ToUpper(strings.TrimPrefix(f, ":"))
		if !sensitiveMarkers[w] && (i > 1 || !sensitiveVerbs[w]) {
			continue
		}
		if i+1 >= len(fields) {
			return line
		}
		return redactTail(fields, i+1)
	}
	return line
}

// redactTail keeps fields[:from] and hides the rest according to the password mode.
func redactTail(fields []string, from int) string {
	secret := strings.Join(fields[from:], " ")
	kept := strings.Join(fields[:from], " ")
	if passwordMode.Load() == passwordsMask {
		return fmt.Sprintf("%s *** (%d)", kept, len(secret))
	}
	return kept
}

func (s *Session) LogCommand(command string, attrs ...slog.Attr) {
	command = redactCommand(command)
	s.commands++
	s.flushConnect()
	args := make([]any, 0, 2+len(attrs))
	args = append(args, slog.String("action", "command"))
	args = append(args, slog.String("command", command))
	for _, a := range attrs {
		args = append(args, a)
	}
	s.Logger.Info("command received", args...)
}

// Log records a fingerprinting or status event that does not count as a command,
// payload or auth attempt, so sessions that only produce such events stay probes.
func (s *Session) Log(msg string, attrs ...slog.Attr) {
	s.flushConnect()
	args := make([]any, 0, 1+len(attrs))
	args = append(args, slog.String("action", "probe"))
	for _, a := range attrs {
		args = append(args, a)
	}
	s.Logger.Info(msg, args...)
}

func (s *Session) LogPayload(payloadType string, attrs ...slog.Attr) {
	n := 0
	for _, a := range attrs {
		if a.Value.Kind() == slog.KindString {
			n += len(a.Value.String())
		}
	}
	s.LogPayloadSize(payloadType, n, attrs...)
}

// LogPayloadSize is LogPayload for callers that log only a bounded sample of the
// data: size is the number of bytes received (at least 1 is counted).
func (s *Session) LogPayloadSize(payloadType string, size int, attrs ...slog.Attr) {
	s.payloads++
	n := max(size, 1)
	s.payloadBytes += n
	s.flushConnect()
	args := make([]any, 0, 2+len(attrs))
	args = append(args, slog.String("action", "payload"))
	args = append(args, slog.String("payload_type", payloadType))
	for _, a := range attrs {
		args = append(args, a)
	}
	s.Logger.Info("payload received", args...)
}

func (s *Session) LogDisconnect() {
	// Probe sessions are aggregated by the sensor: no per-session lines.
	if s.Sensor != nil && s.Transport == alert.TransportTCP && s.Sensor.SessionEnd(s.Info()) {
		return
	}
	s.flushConnect()
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

func LogRejected(logger *slog.Logger, m *metrics.Metrics, protocol string, transport alert.Transport, destPort int, sourceIP, reason string) {
	if m != nil {
		m.SessionsRejected.WithLabelValues(protocol).Inc()
	}
	suppressed, ok := rejectLog.allow(protocol)
	if !ok {
		return
	}
	args := []any{
		"action", "rejected",
		"protocol", protocol,
		"transport", string(transport),
		"dest_port", destPort,
		"source_ip", sourceIP,
		"reason", reason,
	}
	if suppressed > 0 {
		args = append(args, "suppressed", suppressed)
	}
	logger.Warn("connection rejected", args...)
}

// rejectLogInterval is the minimum gap between "connection rejected" warnings per
// protocol; the rejections in between are only counted (the metric is unaffected).
const rejectLogInterval = 10 * time.Second

// rejectLimiter rate limits the rejection warning per protocol, so a flood cannot
// turn the limiter into a log amplifier.
type rejectLimiter struct {
	mu         sync.Mutex
	now        func() time.Time
	last       map[string]time.Time
	suppressed map[string]int
}

func newRejectLimiter(now func() time.Time) *rejectLimiter {
	return &rejectLimiter{now: now, last: map[string]time.Time{}, suppressed: map[string]int{}}
}

// rejectLog is package level state; tests that touch it swap in a fresh instance.
var rejectLog = newRejectLimiter(time.Now)

// allow reports whether a warning may be logged now, with the number of
// rejections suppressed since the previous one.
func (r *rejectLimiter) allow(protocol string) (int, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if last, seen := r.last[protocol]; seen && now.Sub(last) < rejectLogInterval {
		r.suppressed[protocol]++
		return 0, false
	}
	r.last[protocol] = now
	n := r.suppressed[protocol]
	delete(r.suppressed, protocol)
	return n, true
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
	if s.ignored {
		m.IgnoredSessions.WithLabelValues(s.Protocol).Inc()
	}
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
		// Connections accepted but never taken must not leak.
		for c := range ml.connCh {
			c.Close()
		}
	})
	return nil
}

func (ml *MultiListener) Addr() net.Addr {
	return ml.listeners[0].Addr()
}

// ListenMultiTCP listens on all addrs. logger, m and protocol are used to report
// panics recovered in the accept goroutines; logger and m may be nil.
func ListenMultiTCP(ctx context.Context, addrs []string, proxyProto bool, logger *slog.Logger, m *metrics.Metrics, protocol string) (*MultiListener, error) {
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
			ln = newProxyListener(ln, logger, m, protocol)
		}
		listeners = append(listeners, ln)
	}

	return newMultiListener(listeners, logger, m, protocol), nil
}

// acceptPanicBackoffMin and acceptPanicBackoffMax bound the sleep after a
// recovered Accept panic, so a listener that panics on every call cannot spin a CPU.
var (
	acceptPanicBackoffMin = 10 * time.Millisecond
	acceptPanicBackoffMax = time.Second
)

// acceptRetryable reports whether an Accept error should be retried. Only a
// closed listener is final.
func acceptRetryable(err error) bool {
	return !errors.Is(err, net.ErrClosed)
}

func newMultiListener(listeners []net.Listener, logger *slog.Logger, m *metrics.Metrics, protocol string) *MultiListener {
	ml := &MultiListener{
		listeners: listeners,
		connCh:    make(chan net.Conn, 64),
		done:      make(chan struct{}),
	}

	for _, ln := range listeners {
		ml.wg.Add(1)
		go func(l net.Listener) {
			defer ml.wg.Done()
			backoff := acceptPanicBackoffMin
			for {
				var conn net.Conn
				var err error
				panicked := true
				// A panic while accepting (e.g. PROXY header parsing) must not end the loop.
				safely(logger, m, protocol, func() {
					conn, err = l.Accept()
					panicked = false
				})
				if panicked {
					// Back off (10ms doubling to 1s) so repeated panics do not spin.
					select {
					case <-time.After(backoff):
					case <-ml.done:
						return
					}
					if backoff *= 2; backoff > acceptPanicBackoffMax {
						backoff = acceptPanicBackoffMax
					}
					continue
				}
				if err != nil {
					// Only a closed listener ends the loop. Other errors (for
					// example EMFILE when out of file descriptors) are usually
					// transient, so retry with the same bounded backoff.
					if !acceptRetryable(err) {
						return
					}
					if logger != nil {
						LogErrorStandalone(logger, protocol, "accept_failed", err)
					}
					select {
					case <-time.After(backoff):
					case <-ml.done:
						return
					}
					if backoff *= 2; backoff > acceptPanicBackoffMax {
						backoff = acceptPanicBackoffMax
					}
					continue
				}
				backoff = acceptPanicBackoffMin
				if conn == nil {
					continue
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

	return ml
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

// deadlineFromContext returns the earlier of the context deadline and now+timeout.
// An already cancelled context yields a deadline of now, so nothing waits the full
// timeout after shutdown began.
func deadlineFromContext(ctx context.Context, timeout time.Duration) time.Time {
	if ctx.Err() != nil {
		return time.Now()
	}
	if dl, ok := ctx.Deadline(); ok && dl.Before(time.Now().Add(timeout)) {
		return dl
	}
	return time.Now().Add(timeout)
}

// maxCommandNameBytes bounds the command name sent as alert meta.
const maxCommandNameBytes = 32

// commandName returns the first word of line, cut to maxCommandNameBytes at a
// rune boundary, so alert meta never carries arguments or attacker data blobs.
func commandName(line string) string {
	line = strings.TrimSpace(line)
	if i := strings.IndexAny(line, " \t\r\n"); i >= 0 {
		line = line[:i]
	}
	if len(line) > maxCommandNameBytes {
		n := maxCommandNameBytes
		for n > 0 && !utf8.RuneStart(line[n]) {
			n--
		}
		line = line[:n]
	}
	return line
}

// AlertCommand reports a logged command to the sensor with only the command name
// as meta, so the alert is not delayed until the session ends. It is a no-op once
// the session was reported as attack or higher, which keeps command floods cheap;
// later escalation (scan) is reported by the sensor at session end.
func (s *Session) AlertCommand(ctx context.Context, line string) {
	if alert.MaxClass(s.alertedClass, alert.ClassAttack) == s.alertedClass {
		return
	}
	s.Alert(ctx, map[string]string{"command": commandName(line)})
}

// Session outcomes set from I/O errors.
const (
	outcomeTimeout = "timeout"
	outcomeError   = "error"
	outcomeTooLong = "too_long"
)

// isTimeout reports whether err is (or wraps) a network timeout.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// setOutcome records the outcome for an I/O error: timeout, too_long (a line
// longer than the read limit) or error. A nil error leaves the outcome alone.
func setOutcome(sess *Session, err error) {
	switch {
	case err == nil:
	case isTimeout(err):
		sess.SetOutcome(outcomeTimeout)
	case errors.Is(err, bufio.ErrTooLong):
		sess.SetOutcome(outcomeTooLong)
	default:
		sess.SetOutcome(outcomeError)
	}
}

// setReadOutcome is like setOutcome for read errors, but a client that already
// tried credentials and then simply disconnected is not an error.
func (s *Session) setReadOutcome(err error) {
	if !isTimeout(err) && !errors.Is(err, bufio.ErrTooLong) && s.authAttempts > 0 {
		return
	}
	setOutcome(s, err)
}

// Cred logs one captured credential attempt, counts it and reports it to the
// sensor. username and password are alert meta as well as log attributes; extra
// attributes only go to the log.
func (s *Session) Cred(ctx context.Context, m *metrics.Metrics, username, password string, extra ...slog.Attr) {
	attrs := make([]slog.Attr, 0, 2+len(extra))
	attrs = append(attrs, slog.String("username", username), slog.String("password", password))
	attrs = append(attrs, extra...)
	s.LogAuthAttempt(attrs...)
	s.RecordCredentials(m)
	s.Alert(ctx, map[string]string{"username": username, "password": password})
}
