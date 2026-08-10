package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/st0o0/ran/internal/metrics"
)

type alertMsg struct {
	IP       string
	Protocol string
}

type CrowdSecAlerter struct {
	url         string
	apiKey      string
	banDuration string
	logger      *slog.Logger
	metrics     *metrics.Metrics
	client      *http.Client
	ch          chan alertMsg
	done        chan struct{}
}

func NewCrowdSec(url, apiKey string, banDuration time.Duration, logger *slog.Logger, m *metrics.Metrics) *CrowdSecAlerter {
	dur := formatDuration(banDuration)
	a := &CrowdSecAlerter{
		url:         url + "/v1/alerts",
		apiKey:      apiKey,
		banDuration: dur,
		logger:      logger.With("component", "crowdsec"),
		metrics:     m,
		client:      &http.Client{Timeout: 5 * time.Second},
		ch:          make(chan alertMsg, 256),
		done:        make(chan struct{}),
	}
	go a.worker()
	return a
}

func (a *CrowdSecAlerter) Alert(_ context.Context, ip string, protocol string) {
	select {
	case a.ch <- alertMsg{IP: ip, Protocol: protocol}:
	default:
		a.logger.Warn("alert channel full, dropping", "ip", ip, "protocol", protocol)
	}
}

func (a *CrowdSecAlerter) Close() {
	close(a.ch)
	select {
	case <-a.done:
	case <-time.After(5 * time.Second):
		a.logger.Warn("alert drain timeout")
	}
}

func (a *CrowdSecAlerter) worker() {
	defer close(a.done)
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
			Origin:   "crowdsec",
		}},
	}}

	body, err := json.Marshal(alerts)
	if err != nil {
		a.logger.Error("marshal alert", "error", err)
		a.metrics.CrowdSecAlerts.WithLabelValues(msg.Protocol, "failure").Inc()
		return
	}

	req, err := http.NewRequest("POST", a.url, bytes.NewReader(body))
	if err != nil {
		a.logger.Error("create request", "error", err)
		a.metrics.CrowdSecAlerts.WithLabelValues(msg.Protocol, "failure").Inc()
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", a.apiKey)

	resp, err := a.client.Do(req)
	if err != nil {
		a.logger.Warn("push alert failed", "error", err, "ip", msg.IP, "protocol", msg.Protocol)
		a.metrics.CrowdSecAlerts.WithLabelValues(msg.Protocol, "failure").Inc()
		return
	}
	resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		a.logger.Debug("alert pushed", "ip", msg.IP, "protocol", msg.Protocol, "scenario", scenario)
		a.metrics.CrowdSecAlerts.WithLabelValues(msg.Protocol, "success").Inc()
	} else {
		a.logger.Warn("push alert rejected", "status", resp.StatusCode, "ip", msg.IP, "protocol", msg.Protocol)
		a.metrics.CrowdSecAlerts.WithLabelValues(msg.Protocol, "failure").Inc()
	}
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
