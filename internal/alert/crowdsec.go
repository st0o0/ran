package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/st0o0/ran/internal/metrics"
)

// defaultMaxTracked bounds the cooldown, scan and probe log maps.
const defaultMaxTracked = 20000

// DefaultMaxTracked is the default cap of the tracking maps; it must equal the
// default of RAN_CROWDSEC_MAX_TRACKED.
const DefaultMaxTracked = defaultMaxTracked

// DefaultAlertCooldown is the default per-IP and class alert cooldown.
const DefaultAlertCooldown = time.Hour

// Bounds for client controlled event meta, so one alert cannot make a batch POST
// exceed the LAPI request limit (413) and lose the whole batch.
const (
	maxMetaValueBytes = 256
	maxMetaKeyBytes   = 64
	maxMetaKeys       = 32
	// maxBatchBytes is the estimated JSON size at which a batch is flushed early.
	maxBatchBytes = 512 << 10
)

// Bounds for the LAPI client.
const (
	// flushTimeout bounds one flush (both posts and a re-login), and the whole
	// final drain after Close: one drain may do two posts plus a login, so it
	// needs the full window, but never more.
	flushTimeout = 5 * time.Second
	// finalFlushTimeout bounds the last attempt for the pending batch when
	// Close interrupts a failure hold.
	finalFlushTimeout = 2 * time.Second
	// maxResponseBytes bounds any LAPI response body that is decoded.
	maxResponseBytes = 64 << 10
	// maxErrorBodyBytes bounds the response excerpt kept in an error message.
	maxErrorBodyBytes = 1 << 10
)

// failHoldMin is the minimum pause after a failed flush; the worker holds for
// max(batchInterval, failHoldMin) so a down LAPI is not hit once per session.
// failLogInterval rate limits the failure warnings. Both are variables for tests.
var (
	failHoldMin     = time.Second
	failLogInterval = 10 * time.Second
)

// sensorMetaKeys are set by the sensor and always survive the meta bounds.
var sensorMetaKeys = map[string]bool{
	"class": true, "protocol": true, "dest_port": true,
	"auth_attempts": true, "commands": true, "payload_bytes": true,
}

type alertMsg struct {
	IP       string
	Protocol string
	Class    Class
	Meta     map[string]string

	// cooldownKey and slot let a failed POST release the cooldown slot.
	cooldownKey string
	slot        uint64

	// raw is the marshaled alert, set once by encode; its length is the real
	// size (escaping included) used for the early flush.
	raw []byte
}

// encode marshals the alert once and caches the result.
func (m *alertMsg) encode() error {
	if m.raw != nil {
		return nil
	}
	raw, err := json.Marshal(newCSAlert(*m, time.Now().UTC().Format(time.RFC3339)))
	if err != nil {
		return err
	}
	m.raw = raw
	return nil
}

type CrowdSecConfig struct {
	URL       string
	MachineID string
	Password  string
	// BanOn lists the classes that produce an alert; empty means attack and scan.
	BanOn []Class
	// Cooldown allows at most one alert per IP and class per window; 0 disables it.
	Cooldown      time.Duration
	BatchInterval time.Duration
	BatchSize     int
	MaxTracked    int
}

type CrowdSecAlerter struct {
	// ctx is the lifecycle context (login, refresh). Flushes derive a detached
	// context from it, so the final drain still works after it is canceled.
	ctx       context.Context
	alertsURL string
	loginURL  string
	machineID string
	password  string
	logger    *slog.Logger
	metrics   *metrics.Metrics
	client    *http.Client

	mu          sync.RWMutex
	token       string
	tokenExpiry time.Time

	banOn         map[Class]bool
	cooldown      *cooldownFilter
	batchInterval time.Duration
	batchSize     int

	ch     chan alertMsg
	stopCh chan struct{}
	wg     sync.WaitGroup

	// abandon is set by the worker when Close interrupted a hold; the first
	// pending batch then gets one short final attempt (finalTried), the rest is
	// failed without a POST. Worker goroutine only.
	abandon    bool
	finalTried bool

	// drainBy is the unix nano deadline of the final drain, set by Close; 0
	// while running. Every flush after it is clamped to this deadline.
	drainBy atomic.Int64

	// logMu guards the rate limited failure warning.
	logMu      sync.Mutex
	lastWarn   time.Time
	suppressed int

	// closeMu keeps Alert from sending on ch after Close has closed it.
	closeMu sync.RWMutex
	closed  bool
}

type loginRequest struct {
	MachineID string `json:"machine_id"`
	Password  string `json:"password"`
}

type loginResponse struct {
	Token  string `json:"token"`
	Expire string `json:"expire"`
}

func NewCrowdSec(ctx context.Context, cfg CrowdSecConfig, logger *slog.Logger, m *metrics.Metrics) (*CrowdSecAlerter, error) {
	maxTracked := cfg.MaxTracked
	if maxTracked <= 0 {
		maxTracked = defaultMaxTracked
	}

	banOn := make(map[Class]bool, len(Classes))
	for _, c := range cfg.BanOn {
		banOn[c] = true
	}
	if len(cfg.BanOn) == 0 {
		banOn[ClassAttack] = true
		banOn[ClassScan] = true
	}

	batchSize := cfg.BatchSize
	if cfg.BatchInterval == 0 {
		batchSize = 1
	}

	a := &CrowdSecAlerter{
		ctx:           ctx,
		alertsURL:     cfg.URL + "/v1/alerts",
		loginURL:      cfg.URL + "/v1/watchers/login",
		machineID:     cfg.MachineID,
		password:      cfg.Password,
		logger:        logger.With("component", "crowdsec"),
		metrics:       m,
		client:        &http.Client{Timeout: 10 * time.Second},
		banOn:         banOn,
		cooldown:      newCooldownFilter(cfg.Cooldown, maxTracked),
		batchInterval: cfg.BatchInterval,
		batchSize:     batchSize,
		ch:            make(chan alertMsg, 256),
		stopCh:        make(chan struct{}),
	}

	a.cooldown.stats = newTrackStats(m, mapCooldown)

	if err := a.login(ctx); err != nil {
		return nil, fmt.Errorf("crowdsec login: %w", err)
	}

	a.wg.Add(3)
	go a.batchWorker()
	go a.refreshLoop()
	go a.cleanupLoop()
	return a, nil
}

// Submit implements Sink. Every call counts as received, then exactly one of
// invalid, closed, filtered, cooldown, queued or dropped.
func (a *CrowdSecAlerter) Submit(_ context.Context, ev Event) {
	protocol := ev.Info.Protocol
	a.metrics.CrowdSecPipeline.WithLabelValues(protocol, "received").Inc()

	// Only publicly routable addresses may be reported; validate before the
	// cooldown so junk never enters the maps.
	addr, ok := parseBannableIP(ev.Info.SourceIP)
	if !ok {
		a.rejectInvalid(ev.Info.SourceIP, protocol)
		return
	}
	ip := addr.String()

	a.closeMu.RLock()
	defer a.closeMu.RUnlock()
	if a.closed {
		a.logger.Debug("alert filtered", "source_ip", ip, "protocol", protocol, "stage", "closed")
		a.metrics.CrowdSecPipeline.WithLabelValues(protocol, "closed").Inc()
		return
	}

	// A scan outranks the session's own class. When scan is not reported, fall back
	// to what the session did itself, so a scanner's attacks still alert as attack.
	if ev.Class == ClassScan && !a.banOn[ClassScan] {
		ev.Class = Classify(ev.Info)
	}

	if !a.banOn[ev.Class] {
		a.logger.Debug("alert filtered", "source_ip", ip, "protocol", protocol, "class", string(ev.Class), "stage", "filtered")
		a.metrics.CrowdSecPipeline.WithLabelValues(protocol, "filtered").Inc()
		return
	}

	key, slot, ok := a.cooldown.Allow(ip, ev.Class)
	if !ok {
		a.logger.Debug("alert filtered", "source_ip", ip, "protocol", protocol, "class", string(ev.Class), "stage", "cooldown")
		a.metrics.CrowdSecPipeline.WithLabelValues(protocol, "cooldown").Inc()
		return
	}

	msg := alertMsg{IP: ip, Protocol: protocol, Class: ev.Class, Meta: eventMeta(ev), cooldownKey: key, slot: slot}
	select {
	case a.ch <- msg:
		a.metrics.CrowdSecPipeline.WithLabelValues(protocol, "queued").Inc()
		a.metrics.CrowdSecQueueLength.Set(float64(len(a.ch)))
	default:
		// Release the cooldown slot so a retry is not suppressed.
		a.cooldown.Release(key, slot)
		a.logger.Warn("alert filtered", "source_ip", ip, "protocol", protocol, "stage", "dropped")
		a.metrics.CrowdSecPipeline.WithLabelValues(protocol, "dropped").Inc()
		a.metrics.CrowdSecDropped.WithLabelValues(protocol).Inc()
	}
}

// eventMeta merges the trap meta with the sensor meta and bounds the result. The
// sensor keys win so a trap cannot spoof the class or the counters.
func eventMeta(ev Event) map[string]string {
	meta := make(map[string]string, len(ev.Meta)+6)
	for k, v := range ev.Meta {
		meta[k] = v
	}
	meta["class"] = string(ev.Class)
	meta["protocol"] = ev.Info.Protocol
	meta["dest_port"] = strconv.Itoa(ev.Info.DestPort)
	meta["auth_attempts"] = strconv.Itoa(ev.Info.AuthAttempts)
	meta["commands"] = strconv.Itoa(ev.Info.Commands)
	meta["payload_bytes"] = strconv.Itoa(ev.Info.PayloadBytes)
	return boundMeta(meta)
}

// sanitizeMeta replaces control and format characters (newlines, bidi overrides,
// zero width, U+2028/U+2029) with a space and
// cuts s to at most max bytes at a UTF-8 rune boundary.
func sanitizeMeta(s string, max int) string {
	var b strings.Builder
	b.Grow(min(len(s), max))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		if r == utf8.RuneError && size <= 1 {
			r = '?'
		} else if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029 {
			r = ' '
		}
		if b.Len()+utf8.RuneLen(r) > max {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// secretMetaKeys are meta keys that are dropped (compared case insensitively).
var secretMetaKeys = map[string]bool{
	"password": true, "pass": true, "passwd": true,
	"secret": true, "token": true, "authorization": true,
}

// boundMeta drops secret keys, sanitizes keys and values and caps the number of
// keys. Sensor keys always survive; surplus trap keys are dropped in sorted order,
// so the result is deterministic. It is idempotent.
func boundMeta(in map[string]string) map[string]string {
	out := make(map[string]string, min(len(in), maxMetaKeys))
	trapKeys := make([]string, 0, len(in))
	for k, v := range in {
		if sensorMetaKeys[k] {
			out[k] = sanitizeMeta(v, maxMetaValueBytes)
			continue
		}
		if k == "" {
			continue
		}
		// Secrets never leave the host, regardless of RAN_LOG_PASSWORDS.
		if secretMetaKeys[strings.ToLower(strings.TrimSpace(k))] {
			continue
		}
		trapKeys = append(trapKeys, k)
	}
	sort.Strings(trapKeys)
	for _, k := range trapKeys {
		if len(out) >= maxMetaKeys {
			break
		}
		sk := sanitizeMeta(k, maxMetaKeyBytes)
		if sk == "" || sensorMetaKeys[sk] {
			continue
		}
		out[sk] = sanitizeMeta(in[k], maxMetaValueBytes)
	}
	return out
}

// nonGlobalPrefixes lists ranges that are never legitimate scanner sources:
// private, loopback, link-local, multicast, reserved, documentation, CGNAT and
// transition ranges. Spoofed packets and misrouted traffic land here, so they
// must not be banned or pushed to CAPI.
var nonGlobalPrefixes = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
	"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32",
	"2002::/16", "3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10", "ff00::/8", "::/96",
)

func mustPrefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(cidrs))
	for i, c := range cidrs {
		out[i] = netip.MustParsePrefix(c)
	}
	return out
}

// parseBannableIP parses ip, unmaps IPv4-mapped IPv6 and rejects zoned
// addresses and everything in nonGlobalPrefixes.
func parseBannableIP(ip string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, false
	}
	addr = addr.Unmap()
	for _, p := range nonGlobalPrefixes {
		if p.Contains(addr) {
			return netip.Addr{}, false
		}
	}
	return addr, true
}

func (a *CrowdSecAlerter) rejectInvalid(ip, protocol string) {
	a.logger.Debug("alert filtered", "source_ip", ip, "protocol", protocol, "stage", "invalid")
	a.metrics.CrowdSecPipeline.WithLabelValues(protocol, "invalid").Inc()
}

// Close stops the alerter and drains the queue, waiting at most flushTimeout.
func (a *CrowdSecAlerter) Close() {
	a.CloseContext(context.Background())
}

// CloseContext is Close with a caller supplied budget: the final drain is
// capped at flushTimeout and at the deadline of ctx, whichever is sooner, so a
// shared shutdown deadline is never exceeded.
func (a *CrowdSecAlerter) CloseContext(ctx context.Context) {
	a.closeMu.Lock()
	if a.closed {
		a.closeMu.Unlock()
		return
	}
	a.closed = true
	limit := time.Now().Add(flushTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(limit) {
		limit = dl
	}
	a.drainBy.Store(limit.UnixNano())
	close(a.stopCh)
	close(a.ch)
	a.closeMu.Unlock()
	done := make(chan struct{})
	go func() {
		a.wg.Wait()
		close(done)
	}()
	timer := time.NewTimer(time.Until(limit) + 100*time.Millisecond)
	defer timer.Stop()
	select {
	case <-done:
	case <-ctx.Done():
		a.logger.Warn("alert drain canceled")
	case <-timer.C:
		a.logger.Warn("alert drain timeout")
	}
}

func (a *CrowdSecAlerter) login(ctx context.Context) error {
	token, expiry, err := a.doLogin(ctx)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.token = token
	a.tokenExpiry = expiry
	a.mu.Unlock()
	a.logger.Debug("login successful", "expires", expiry)
	return nil
}

func (a *CrowdSecAlerter) doLogin(ctx context.Context) (string, time.Time, error) {
	body, err := json.Marshal(loginRequest{
		MachineID: a.machineID,
		Password:  a.password,
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("marshal login request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.loginURL, bytes.NewReader(body))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("create login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("login request: %w", err)
	}
	defer drainClose(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return "", time.Time{}, fmt.Errorf("login failed (status %d): %s", resp.StatusCode, string(respBody))
	}

	var lr loginResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&lr); err != nil {
		return "", time.Time{}, fmt.Errorf("decode login response: %w", err)
	}

	expiry, err := time.Parse(time.RFC3339, lr.Expire)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("parse token expiry: %w", err)
	}

	return lr.Token, expiry, nil
}

func (a *CrowdSecAlerter) refreshLoop() {
	defer a.wg.Done()
	for {
		a.mu.RLock()
		expiry := a.tokenExpiry
		a.mu.RUnlock()

		lifetime := time.Until(expiry)
		refreshAt := time.Duration(float64(lifetime) * 0.8)
		if refreshAt < time.Second {
			refreshAt = time.Second
		}

		timer := time.NewTimer(refreshAt)
		select {
		case <-timer.C:
		case <-a.ctx.Done():
			timer.Stop()
			return
		case <-a.stopCh:
			timer.Stop()
			return
		}

		backoff := 10 * time.Second
		for {
			if err := a.login(a.ctx); err != nil {
				a.logger.Warn("token refresh failed", "error", err, "retry_in", backoff)
				retryTimer := time.NewTimer(backoff)
				select {
				case <-retryTimer.C:
				case <-a.ctx.Done():
					retryTimer.Stop()
					return
				case <-a.stopCh:
					retryTimer.Stop()
					return
				}
				backoff *= 2
				if backoff > 60*time.Second {
					backoff = 60 * time.Second
				}
				continue
			}
			break
		}
	}
}

func (a *CrowdSecAlerter) batchWorker() {
	defer a.wg.Done()

	if a.batchInterval == 0 {
		for msg := range a.ch {
			a.metrics.CrowdSecQueueLength.Set(float64(len(a.ch)))
			a.send([]alertMsg{msg})
		}
		return
	}

	ticker := time.NewTicker(a.batchInterval)
	defer ticker.Stop()
	var batch []alertMsg
	batchBytes := 0

	for {
		select {
		case msg, ok := <-a.ch:
			a.metrics.CrowdSecQueueLength.Set(float64(len(a.ch)))
			if !ok {
				a.send(batch)
				return
			}
			if err := msg.encode(); err != nil {
				a.logger.Error("marshal alert", "error", err)
				a.failBatch([]alertMsg{msg})
				continue
			}
			// Flush early so one batch never exceeds the LAPI request limit.
			sz := len(msg.raw)
			if len(batch) > 0 && batchBytes+sz > maxBatchBytes {
				a.send(batch)
				batch, batchBytes = nil, 0
			}
			batch = append(batch, msg)
			batchBytes += sz
			if len(batch) >= a.batchSize {
				a.send(batch)
				batch, batchBytes = nil, 0
			}
		case <-ticker.C:
			if len(batch) > 0 {
				a.send(batch)
				batch, batchBytes = nil, 0
			}
		}
	}
}

func (a *CrowdSecAlerter) cleanupLoop() {
	defer a.wg.Done()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			a.cooldown.cleanup()
		case <-a.stopCh:
			return
		}
	}
}

func buildEventMeta(meta map[string]string) []csMeta {
	if len(meta) == 0 {
		return []csMeta{}
	}
	meta = boundMeta(meta)
	keys := make([]string, 0, len(meta))
	for k := range meta {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]csMeta, len(keys))
	for i, k := range keys {
		out[i] = csMeta{Key: k, Value: meta[k]}
	}
	return out
}

func newCSAlert(msg alertMsg, now string) csAlert {
	return csAlert{
		Scenario:        "custom/ran-" + msg.Protocol + "-trap",
		ScenarioHash:    "",
		ScenarioVersion: "",
		Message:         fmt.Sprintf("Honeypot %s trap triggered by %s", msg.Protocol, msg.IP),
		EventsCount:     1,
		StartAt:         now,
		StopAt:          now,
		Capacity:        0,
		Leakspeed:       "0",
		Simulated:       false,
		// Alerts carry no decisions: CrowdSec profiles decide the ban, and
		// remediation lets them create a decision from the alert.
		Remediation: true,
		Events: []csEvent{{
			Timestamp: now,
			Meta:      buildEventMeta(msg.Meta),
		}},
		// Both IP (geo enrichment) and Value (profile decisions) are required.
		Source: csSource{
			Scope: "Ip",
			IP:    msg.IP,
			Value: msg.IP,
		},
		Decisions: []csDecision{},
	}
}

// send flushes the batch and, after a failure, holds the worker so retries are
// paced instead of one POST (and login) per attacker session. Once Close
// interrupts a hold, the rest is failed without posting.
func (a *CrowdSecAlerter) send(batch []alertMsg) {
	if len(batch) == 0 {
		return
	}
	if a.abandon {
		// One last short attempt for the first pending batch: the LAPI may be
		// back by now. Everything after it is failed without a POST.
		if !a.finalTried {
			a.finalTried = true
			if a.flushWithin(batch, finalFlushTimeout) {
				a.abandon = false
			}
			return
		}
		a.failBatch(batch)
		return
	}
	if !a.flush(batch) && !a.hold() {
		a.abandon = true
	}
}

// hold waits max(batchInterval, failHoldMin) and reports false if Close came first.
func (a *CrowdSecAlerter) hold() bool {
	timer := time.NewTimer(max(a.batchInterval, failHoldMin))
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-a.stopCh:
		return false
	}
}

// warnLimited logs a failure warning at most once per failLogInterval and reports
// the number of suppressed warnings with the next one.
func (a *CrowdSecAlerter) warnLimited(msg string, args ...any) {
	a.logMu.Lock()
	now := time.Now()
	if !a.lastWarn.IsZero() && now.Sub(a.lastWarn) < failLogInterval {
		a.suppressed++
		a.logMu.Unlock()
		return
	}
	a.lastWarn = now
	suppressed := a.suppressed
	a.suppressed = 0
	a.logMu.Unlock()
	if suppressed > 0 {
		args = append(args, "suppressed", suppressed)
	}
	a.logger.Warn(msg, args...)
}

// flush posts the batch and reports whether the LAPI accepted it.
func (a *CrowdSecAlerter) flush(batch []alertMsg) bool {
	return a.flushWithin(batch, flushTimeout)
}

// flushWithin is flush with an explicit timeout for the whole attempt (posts and
// re-login). After Close started, the attempt is also clamped to the drain
// deadline.
func (a *CrowdSecAlerter) flushWithin(batch []alertMsg, timeout time.Duration) bool {
	if len(batch) == 0 {
		return true
	}

	var buf bytes.Buffer
	buf.WriteByte('[')
	for i := range batch {
		if err := batch[i].encode(); err != nil {
			a.logger.Error("marshal alert", "error", err)
			a.failBatch(batch)
			return false
		}
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(batch[i].raw)
	}
	buf.WriteByte(']')
	body := buf.Bytes()

	// Detach from the lifecycle context so the final drain still posts after
	// shutdown started; the timeout bounds each attempt.
	deadline := time.Now().Add(timeout)
	if by := a.drainBy.Load(); by != 0 {
		if d := time.Unix(0, by); d.Before(deadline) {
			deadline = d
		}
	}
	ctx, cancel := context.WithDeadline(context.WithoutCancel(a.ctx), deadline)
	defer cancel()

	started := time.Now()
	status, err := a.doPost(ctx, body)
	if status == http.StatusUnauthorized {
		if lerr := a.login(ctx); lerr != nil {
			a.metrics.CrowdSecPushDuration.Observe(time.Since(started).Seconds())
			a.metrics.CrowdSecPushErrors.Inc()
			a.warnLimited("re-login after 401 failed", "error", lerr)
			a.failBatch(batch)
			return false
		}
		status, err = a.doPost(ctx, body)
	}
	a.metrics.CrowdSecPushDuration.Observe(time.Since(started).Seconds())

	if err == nil && status >= 200 && status < 300 {
		for _, msg := range batch {
			a.logger.Debug("alert sent", "source_ip", msg.IP, "protocol", msg.Protocol, "stage", "sent")
			a.metrics.CrowdSecPipeline.WithLabelValues(msg.Protocol, "sent").Inc()
		}
		return true
	}
	a.metrics.CrowdSecPushErrors.Inc()
	if err != nil {
		a.warnLimited("push alert batch rejected", "status", status, "count", len(batch), "error", err)
	} else {
		a.warnLimited("push alert batch rejected", "status", status, "count", len(batch))
	}
	a.failBatch(batch)
	return false
}

// failBatch counts a failed batch and releases the cooldown slots of its alerts,
// so the sources are reported again once the LAPI is back instead of staying
// unreported for the whole cooldown.
func (a *CrowdSecAlerter) failBatch(batch []alertMsg) {
	for _, msg := range batch {
		a.metrics.CrowdSecPipeline.WithLabelValues(msg.Protocol, "failed").Inc()
		if msg.cooldownKey != "" {
			a.cooldown.Release(msg.cooldownKey, msg.slot)
			a.metrics.CrowdSecPipeline.WithLabelValues(msg.Protocol, "released").Inc()
		}
	}
}

// doPost sends the alert body and returns the HTTP status code. A transport
// error is returned with status -1; the caller logs it once.
func (a *CrowdSecAlerter) doPost(ctx context.Context, body []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.alertsURL, bytes.NewReader(body))
	if err != nil {
		return -1, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	a.mu.RLock()
	req.Header.Set("Authorization", "Bearer "+a.token)
	a.mu.RUnlock()

	resp, err := a.client.Do(req)
	if err != nil {
		return -1, fmt.Errorf("push alerts: %w", err)
	}
	drainClose(resp.Body)
	return resp.StatusCode, nil
}

// drainClose reads at most maxResponseBytes of the remaining body, so the
// connection can be reused, and closes it.
func drainClose(body io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, maxResponseBytes))
	_ = body.Close()
}

type csAlert struct {
	Scenario        string       `json:"scenario"`
	ScenarioHash    string       `json:"scenario_hash"`
	ScenarioVersion string       `json:"scenario_version"`
	Message         string       `json:"message"`
	EventsCount     int          `json:"events_count"`
	StartAt         string       `json:"start_at"`
	StopAt          string       `json:"stop_at"`
	Capacity        int          `json:"capacity"`
	Leakspeed       string       `json:"leakspeed"`
	Simulated       bool         `json:"simulated"`
	Remediation     bool         `json:"remediation"`
	Events          []csEvent    `json:"events"`
	Source          csSource     `json:"source"`
	Decisions       []csDecision `json:"decisions"`
}

type csEvent struct {
	Timestamp string   `json:"timestamp"`
	Meta      []csMeta `json:"meta"`
}

type csMeta struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type csSource struct {
	Scope string `json:"scope"`
	IP    string `json:"ip"`
	Value string `json:"value"`
}

type csDecision struct {
	Duration string `json:"duration"`
	Scenario string `json:"scenario"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Type     string `json:"type"`
	Origin   string `json:"origin"`
}

// SanitizeValue applies the meta value bounds (control and format characters
// replaced, cut at 256 bytes) to a client supplied string, so that log lines
// carry the same bounded text as alert meta.
func SanitizeValue(s string) string {
	return sanitizeMeta(s, maxMetaValueBytes)
}
