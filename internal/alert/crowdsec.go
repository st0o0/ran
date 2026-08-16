package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/st0o0/ran/internal/metrics"
)

type alertMsg struct {
	IP       string
	Protocol string
}

type CrowdSecAlerter struct {
	alertsURL   string
	loginURL    string
	machineID   string
	password    string
	banDuration string
	logger      *slog.Logger
	metrics     *metrics.Metrics
	client      *http.Client

	mu          sync.RWMutex
	token       string
	tokenExpiry time.Time

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

func NewCrowdSec(url, machineID, password string, banDuration time.Duration, logger *slog.Logger, m *metrics.Metrics) (*CrowdSecAlerter, error) {
	dur := formatDuration(banDuration)
	a := &CrowdSecAlerter{
		alertsURL:   url + "/v1/alerts",
		loginURL:    url + "/v1/watchers/login",
		machineID:   machineID,
		password:    password,
		banDuration: dur,
		logger:      logger.With("component", "crowdsec"),
		metrics:     m,
		client:      &http.Client{Timeout: 10 * time.Second},
		ch:          make(chan alertMsg, 256),
		stopCh:      make(chan struct{}),
	}

	if err := a.login(); err != nil {
		return nil, fmt.Errorf("crowdsec login: %w", err)
	}

	a.wg.Add(2)
	go a.worker()
	go a.refreshLoop()
	return a, nil
}

func (a *CrowdSecAlerter) Alert(_ context.Context, ip string, protocol string) {
	select {
	case a.ch <- alertMsg{IP: ip, Protocol: protocol}:
	default:
		a.logger.Warn("alert channel full, dropping", "ip", ip, "protocol", protocol)
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

func (a *CrowdSecAlerter) worker() {
	defer a.wg.Done()
	for msg := range a.ch {
		a.push(msg)
	}
}

func (a *CrowdSecAlerter) push(msg alertMsg) {
	scenario := "custom/ran-" + msg.Protocol + "-trap"
	now := time.Now().UTC().Format(time.RFC3339)

	alerts := []csAlert{{
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
		Source: csSource{
			Scope: "ip",
			Value: msg.IP,
		},
		Decisions: []csDecision{{
			Duration: a.banDuration,
			Scenario: scenario,
			Scope:    "ip",
			Value:    msg.IP,
			Type:     "ban",
			Origin:   "ran",
		}},
	}}

	body, err := json.Marshal(alerts)
	if err != nil {
		a.logger.Error("marshal alert", "error", err)
		a.metrics.CrowdSecAlerts.WithLabelValues(msg.Protocol, "failure").Inc()
		return
	}

	status := a.doPost(body)
	if status == 401 {
		a.mu.Lock()
		if err := a.loginLocked(); err != nil {
			a.mu.Unlock()
			a.logger.Warn("re-login after 401 failed", "error", err, "ip", msg.IP, "protocol", msg.Protocol)
			a.metrics.CrowdSecAlerts.WithLabelValues(msg.Protocol, "failure").Inc()
			return
		}
		a.mu.Unlock()
		status = a.doPost(body)
	}

	if status >= 200 && status < 300 {
		a.logger.Debug("alert pushed", "ip", msg.IP, "protocol", msg.Protocol, "scenario", scenario)
		a.metrics.CrowdSecAlerts.WithLabelValues(msg.Protocol, "success").Inc()
	} else {
		a.logger.Warn("push alert rejected", "status", status, "ip", msg.IP, "protocol", msg.Protocol)
		a.metrics.CrowdSecAlerts.WithLabelValues(msg.Protocol, "failure").Inc()
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
	Source          csSource     `json:"source"`
	Decisions       []csDecision `json:"decisions"`
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
