package config

import (
	"log/slog"
	"testing"
	"time"
)

func envFunc(m map[string]string) func(string) string {
	return func(key string) string { return m[key] }
}

func TestDefaults(t *testing.T) {
	_, err := Load(envFunc(map[string]string{"RAN_SSH": "on"}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDefaultValues(t *testing.T) {
	c, _ := Load(envFunc(map[string]string{"RAN_SSH": "on"}))
	if c.SSHAddr != ":2222" {
		t.Errorf("SSHAddr = %q, want :2222", c.SSHAddr)
	}
	if c.HTTPAddr != ":8081" {
		t.Errorf("HTTPAddr = %q, want :8081", c.HTTPAddr)
	}
	if c.MySQLAddr != ":3307" {
		t.Errorf("MySQLAddr = %q, want :3307", c.MySQLAddr)
	}
	if c.LogLevel != slog.LevelInfo {
		t.Errorf("LogLevel = %v, want INFO", c.LogLevel)
	}
	if c.LogFormat != "json" {
		t.Errorf("LogFormat = %q, want json", c.LogFormat)
	}
	if c.MetricsAddr != ":9550" {
		t.Errorf("MetricsAddr = %q, want :9550", c.MetricsAddr)
	}
	if c.SessionTimeout != 30*time.Second {
		t.Errorf("SessionTimeout = %v, want 30s", c.SessionTimeout)
	}
	if c.MaxSessions != 500 {
		t.Errorf("MaxSessions = %d, want 500", c.MaxSessions)
	}
	if c.MaxPerIP != 10 {
		t.Errorf("MaxPerIP = %d, want 10", c.MaxPerIP)
	}
}

func TestToggles(t *testing.T) {
	c, err := Load(envFunc(map[string]string{
		"RAN_SSH":   "on",
		"RAN_HTTP":  "on",
		"RAN_MYSQL": "off",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !c.SSH {
		t.Error("SSH should be on")
	}
	if !c.HTTP {
		t.Error("HTTP should be on")
	}
	if c.MySQL {
		t.Error("MySQL should be off")
	}
}

func TestNoTrapsEnabled(t *testing.T) {
	_, err := Load(envFunc(map[string]string{}))
	if err == nil {
		t.Fatal("expected error when no traps enabled")
	}
}

func TestInvalidToggle(t *testing.T) {
	_, err := Load(envFunc(map[string]string{"RAN_SSH": "banana"}))
	if err == nil {
		t.Fatal("expected error for invalid toggle")
	}
}

func TestDurationParsing(t *testing.T) {
	c, err := Load(envFunc(map[string]string{
		"RAN_SSH":             "on",
		"RAN_SESSION_TIMEOUT": "1m",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.SessionTimeout != time.Minute {
		t.Errorf("SessionTimeout = %v, want 1m", c.SessionTimeout)
	}
}

func TestInvalidDuration(t *testing.T) {
	_, err := Load(envFunc(map[string]string{
		"RAN_SSH":             "on",
		"RAN_SESSION_TIMEOUT": "banana",
	}))
	if err == nil {
		t.Fatal("expected error for invalid duration")
	}
}

func TestLogLevel(t *testing.T) {
	c, err := Load(envFunc(map[string]string{
		"RAN_SSH":       "on",
		"RAN_LOG_LEVEL": "debug",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.LogLevel != slog.LevelDebug {
		t.Errorf("LogLevel = %v, want DEBUG", c.LogLevel)
	}
}

func TestInvalidLogLevel(t *testing.T) {
	_, err := Load(envFunc(map[string]string{
		"RAN_SSH":       "on",
		"RAN_LOG_LEVEL": "verbose",
	}))
	if err == nil {
		t.Fatal("expected error for invalid log level")
	}
}

func TestCustomAddresses(t *testing.T) {
	c, err := Load(envFunc(map[string]string{
		"RAN_SSH":        "on",
		"RAN_SSH_ADDR":   ":2200",
		"RAN_HTTP_ADDR":  ":9090",
		"RAN_MYSQL_ADDR": ":3308",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.SSHAddr != ":2200" {
		t.Errorf("SSHAddr = %q, want :2200", c.SSHAddr)
	}
	if c.HTTPAddr != ":9090" {
		t.Errorf("HTTPAddr = %q, want :9090", c.HTTPAddr)
	}
	if c.MySQLAddr != ":3308" {
		t.Errorf("MySQLAddr = %q, want :3308", c.MySQLAddr)
	}
}

func TestCrowdSecEnabled(t *testing.T) {
	c, err := Load(envFunc(map[string]string{
		"RAN_SSH":               "on",
		"RAN_CROWDSEC":          "on",
		"RAN_CROWDSEC_URL":      "http://crowdsec:8080",
		"RAN_CROWDSEC_API_KEY":  "abc123",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !c.CrowdSec {
		t.Error("CrowdSec should be on")
	}
	if c.CrowdSecURL != "http://crowdsec:8080" {
		t.Errorf("CrowdSecURL = %q", c.CrowdSecURL)
	}
	if c.CrowdSecBanDuration != 4*time.Hour {
		t.Errorf("CrowdSecBanDuration = %v, want 4h", c.CrowdSecBanDuration)
	}
}

func TestCrowdSecMissingURL(t *testing.T) {
	_, err := Load(envFunc(map[string]string{
		"RAN_SSH":              "on",
		"RAN_CROWDSEC":         "on",
		"RAN_CROWDSEC_API_KEY": "abc123",
	}))
	if err == nil {
		t.Fatal("expected error when CrowdSec enabled without URL")
	}
}

func TestCrowdSecMissingKey(t *testing.T) {
	_, err := Load(envFunc(map[string]string{
		"RAN_SSH":          "on",
		"RAN_CROWDSEC":     "on",
		"RAN_CROWDSEC_URL": "http://crowdsec:8080",
	}))
	if err == nil {
		t.Fatal("expected error when CrowdSec enabled without API key")
	}
}

func TestCrowdSecPermanentBan(t *testing.T) {
	c, err := Load(envFunc(map[string]string{
		"RAN_SSH":                      "on",
		"RAN_CROWDSEC":                 "on",
		"RAN_CROWDSEC_URL":             "http://crowdsec:8080",
		"RAN_CROWDSEC_API_KEY":         "abc123",
		"RAN_CROWDSEC_BAN_DURATION":    "0",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.CrowdSecBanDuration != 0 {
		t.Errorf("CrowdSecBanDuration = %v, want 0 (permanent)", c.CrowdSecBanDuration)
	}
}

func TestCrowdSecCustomDuration(t *testing.T) {
	c, err := Load(envFunc(map[string]string{
		"RAN_SSH":                      "on",
		"RAN_CROWDSEC":                 "on",
		"RAN_CROWDSEC_URL":             "http://crowdsec:8080",
		"RAN_CROWDSEC_API_KEY":         "abc123",
		"RAN_CROWDSEC_BAN_DURATION":    "24h",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.CrowdSecBanDuration != 24*time.Hour {
		t.Errorf("CrowdSecBanDuration = %v, want 24h", c.CrowdSecBanDuration)
	}
}

func TestCustomLimits(t *testing.T) {
	c, err := Load(envFunc(map[string]string{
		"RAN_SSH":          "on",
		"RAN_MAX_SESSIONS": "200",
		"RAN_MAX_PER_IP":   "5",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.MaxSessions != 200 {
		t.Errorf("MaxSessions = %d, want 200", c.MaxSessions)
	}
	if c.MaxPerIP != 5 {
		t.Errorf("MaxPerIP = %d, want 5", c.MaxPerIP)
	}
}
