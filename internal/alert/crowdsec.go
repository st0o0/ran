package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/st0o0/ran/internal/metrics"
)

type alertMsg struct {
	IP       string
	Protocol string
	Meta     map[string]string
}

type CrowdSecConfig struct {
	URL           string
	MachineID     string
	Password      string
	BanDuration   time.Duration
	DedupWindow   time.Duration
	BatchInterval time.Duration
	BatchSize     int
	DecisionCache bool
}

type CrowdSecAlerter struct {
	alertsURL      string
	loginURL       string
	machineID      string
	password       string
	banDuration    string
	banDurationRaw time.Duration
	logger         *slog.Logger
	metrics        *metrics.Metrics
	client         *http.Client

	mu          sync.RWMutex
	token       string
	tokenExpiry time.Time

	dedup         *dedupFilter
	decisionCache DecisionCache
	batchInterval time.Duration
	batchSize     int

	ch     chan alertMsg
	stopCh chan struct{}
	wg     sync.WaitGroup
}

type loginRequest struct {
	MachineID string `json:"machine_id"`
	Password  string `json:"password"`
}

type loginResponse struct {
	Token  string `json:"token"`
	Expire string `json:"expire"`
}

func NewCrowdSec(cfg CrowdSecConfig, logger *slog.Logger, m *metrics.Metrics) (*CrowdSecAlerter, error) {
	var dc DecisionCache
	if cfg.DecisionCache {
		dc = newLocalDecisionCache()
	} else {
		dc = noopDecisionCache{}
	}

	batchSize := cfg.BatchSize
	if cfg.BatchInterval == 0 {
		batchSize = 1
	}

	a := &CrowdSecAlerter{
		alertsURL:      cfg.URL + "/v1/alerts",
		loginURL:       cfg.URL + "/v1/watchers/login",
		machineID:      cfg.MachineID,
		password:       cfg.Password,
		banDuration:    formatDuration(cfg.BanDuration),
		banDurationRaw: cfg.BanDuration,
		logger:         logger.With("component", "crowdsec"),
		metrics:        m,
		client:         &http.Client{Timeout: 10 * time.Second},
		dedup:          newDedupFilter(cfg.DedupWindow),
		decisionCache:  dc,
		batchInterval:  cfg.BatchInterval,
		batchSize:      batchSize,
		ch:             make(chan alertMsg, 256),
		stopCh:         make(chan struct{}),
	}

	if err := a.login(); err != nil {
		return nil, fmt.Errorf("crowdsec login: %w", err)
	}

	a.wg.Add(3)
	go a.batchWorker()
	go a.refreshLoop()
	go a.cleanupLoop()
	return a, nil
}

func (a *CrowdSecAlerter) Alert(_ context.Context, ip string, protocol string, meta map[string]string) {
	a.metrics.CrowdSecPipeline.WithLabelValues(protocol, "received").Inc()

	if a.decisionCache.IsBanned(ip) {
		a.logger.Debug("alert filtered", "source_ip", ip, "protocol", protocol, "stage", "cached")
		a.metrics.CrowdSecPipeline.WithLabelValues(protocol, "cached").Inc()
		return
	}

	scenario := "custom/ran-" + protocol + "-trap"
	if !a.dedup.Allow(ip + "|" + scenario) {
		a.logger.Debug("alert filtered", "source_ip", ip, "protocol", protocol, "stage", "deduplicated")
		a.metrics.CrowdSecPipeline.WithLabelValues(protocol, "deduplicated").Inc()
		return
	}

	select {
	case a.ch <- alertMsg{IP: ip, Protocol: protocol, Meta: meta}:
		a.metrics.CrowdSecPipeline.WithLabelValues(protocol, "queued").Inc()
	default:
		a.logger.Warn("alert filtered", "source_ip", ip, "protocol", protocol, "stage", "dropped")
		a.metrics.CrowdSecPipeline.WithLabelValues(protocol, "dropped").Inc()
		a.metrics.CrowdSecDropped.WithLabelValues(protocol).Inc()
	}
}

func (a *CrowdSecAlerter) Close() {
	close(a.stopCh)
	close(a.ch)
	done := make(chan struct{})
	go func() {
		a.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		a.logger.Warn("alert drain timeout")
	}
}

func (a *CrowdSecAlerter) login() error {
	token, expiry, err := a.doLogin()
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

// loginLocked is like login but assumes mu is already held for writing.
func (a *CrowdSecAlerter) loginLocked() error {
	token, expiry, err := a.doLogin()
	if err != nil {
		return err
	}
	a.token = token
	a.tokenExpiry = expiry
	a.logger.Debug("login successful", "expires", expiry)
	return nil
}

func (a *CrowdSecAlerter) doLogin() (string, time.Time, error) {
	body, err := json.Marshal(loginRequest{
		MachineID: a.machineID,
		Password:  a.password,
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("marshal login request: %w", err)
	}

	req, err := http.NewRequest("POST", a.loginURL, bytes.NewReader(body))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("create login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("login request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return "", time.Time{}, fmt.Errorf("login failed (status %d): %s", resp.StatusCode, string(respBody))
	}

	var lr loginResponse
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
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
		case <-a.stopCh:
			timer.Stop()
			return
		}

		backoff := 10 * time.Second
		for {
			if err := a.login(); err != nil {
				a.logger.Warn("token refresh failed", "error", err, "retry_in", backoff)
				retryTimer := time.NewTimer(backoff)
				select {
				case <-retryTimer.C:
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
			a.flush([]alertMsg{msg})
		}
		return
	}

	ticker := time.NewTicker(a.batchInterval)
	defer ticker.Stop()
	var batch []alertMsg

	for {
		select {
		case msg, ok := <-a.ch:
			if !ok {
				a.flush(batch)
				return
			}
			batch = append(batch, msg)
			if len(batch) >= a.batchSize {
				a.flush(batch)
				batch = nil
			}
		case <-ticker.C:
			if len(batch) > 0 {
				a.flush(batch)
				batch = nil
			}
		}
	}
}

func (a *CrowdSecAlerter) cleanupLoop() {
	defer a.wg.Done()
	interval := a.dedup.window
	if interval == 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			a.dedup.cleanup()
			if ldc, ok := a.decisionCache.(*localDecisionCache); ok {
				ldc.cleanup()
			}
		case <-a.stopCh:
			return
		}
	}
}

func buildEventMeta(meta map[string]string) []csMeta {
	if len(meta) == 0 {
		return []csMeta{}
	}
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

func (a *CrowdSecAlerter) flush(batch []alertMsg) {
	if len(batch) == 0 {
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	alerts := make([]csAlert, len(batch))
	for i, msg := range batch {
		scenario := "custom/ran-" + msg.Protocol + "-trap"
		alerts[i] = csAlert{
			Scenario:        scenario,
			ScenarioHash:    "",
			ScenarioVersion: "",
			Message:         fmt.Sprintf("Honeypot %s trap triggered by %s", msg.Protocol, msg.IP),
			EventsCount:     1,
			StartAt:         now,
			StopAt:          now,
			Capacity:        0,
			Leakspeed:       "0",
			Simulated:       false,
			Events: []csEvent{{
				Timestamp: now,
				Meta:      buildEventMeta(msg.Meta),
			}},
			Source: csSource{
				Scope: "Ip",
				Value: msg.IP,
			},
			Decisions: []csDecision{{
				Duration: a.banDuration,
				Scenario: scenario,
				Scope:    "Ip",
				Value:    msg.IP,
				Type:     "ban",
				Origin:   "ran",
			}},
		}
	}

	body, err := json.Marshal(alerts)
	if err != nil {
		a.logger.Error("marshal alert", "error", err)
		for _, msg := range batch {
			a.metrics.CrowdSecPipeline.WithLabelValues(msg.Protocol, "failed").Inc()
		}
		return
	}

	status := a.doPost(body)
	if status == 401 {
		a.mu.Lock()
		if err := a.loginLocked(); err != nil {
			a.mu.Unlock()
			a.logger.Warn("re-login after 401 failed", "error", err)
			for _, msg := range batch {
				a.metrics.CrowdSecPipeline.WithLabelValues(msg.Protocol, "failed").Inc()
			}
			return
		}
		a.mu.Unlock()
		status = a.doPost(body)
	}

	if status >= 200 && status < 300 {
		for _, msg := range batch {
			a.logger.Debug("alert sent", "source_ip", msg.IP, "protocol", msg.Protocol, "stage", "sent")
			a.metrics.CrowdSecPipeline.WithLabelValues(msg.Protocol, "sent").Inc()
			a.decisionCache.MarkBanned(msg.IP, a.banDurationRaw)
		}
	} else {
		a.logger.Warn("push alert batch rejected", "status", status, "count", len(batch))
		for _, msg := range batch {
			a.metrics.CrowdSecPipeline.WithLabelValues(msg.Protocol, "failed").Inc()
		}
	}
}

// doPost sends the alert body and returns the HTTP status code, or -1 on error.
func (a *CrowdSecAlerter) doPost(body []byte) int {
	req, err := http.NewRequest("POST", a.alertsURL, bytes.NewReader(body))
	if err != nil {
		a.logger.Error("create request", "error", err)
		return -1
	}
	req.Header.Set("Content-Type", "application/json")

	a.mu.RLock()
	req.Header.Set("Authorization", "Bearer "+a.token)
	a.mu.RUnlock()

	resp, err := a.client.Do(req)
	if err != nil {
		a.logger.Warn("push alert failed", "error", err)
		return -1
	}
	resp.Body.Close()
	return resp.StatusCode
}

func formatDuration(d time.Duration) string {
	if d == 0 {
		return "0"
	}
	return d.String()
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
