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
	_, err := Load(envFunc(map[string]string{"RAN_TRAPS": "ssh"}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDefaultValues(t *testing.T) {
	c, _ := Load(envFunc(map[string]string{"RAN_TRAPS": "ssh"}))
	if c.TrapAddr("ssh") != ":2222" {
		t.Errorf("TrapAddr(ssh) = %q, want :2222", c.TrapAddr("ssh"))
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
	if c.SSHHostKeyPath != "/data/ssh_host_key" {
		t.Errorf("SSHHostKeyPath = %q, want /data/ssh_host_key", c.SSHHostKeyPath)
	}
}

func TestSSHHostKeyPathCustom(t *testing.T) {
	c, err := Load(envFunc(map[string]string{
		"RAN_TRAPS":              "ssh",
		"RAN_SSH_HOST_KEY_PATH": "/custom/path/key",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.SSHHostKeyPath != "/custom/path/key" {
		t.Errorf("SSHHostKeyPath = %q, want /custom/path/key", c.SSHHostKeyPath)
	}
}

func TestNoTrapsEnabled(t *testing.T) {
	_, err := Load(envFunc(map[string]string{}))
	if err == nil {
		t.Fatal("expected error when no traps enabled")
	}
}

func TestDurationParsing(t *testing.T) {
	c, err := Load(envFunc(map[string]string{
		"RAN_TRAPS":           "ssh",
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
		"RAN_TRAPS":           "ssh",
		"RAN_SESSION_TIMEOUT": "banana",
	}))
	if err == nil {
		t.Fatal("expected error for invalid duration")
	}
}

func TestLogLevel(t *testing.T) {
	c, err := Load(envFunc(map[string]string{
		"RAN_TRAPS":     "ssh",
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
		"RAN_TRAPS":     "ssh",
		"RAN_LOG_LEVEL": "verbose",
	}))
	if err == nil {
		t.Fatal("expected error for invalid log level")
	}
}

func TestCustomAddresses(t *testing.T) {
	c, err := Load(envFunc(map[string]string{
		"RAN_TRAPS":    "ssh",
		"RAN_SSH_ADDR": ":2200",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.TrapAddr("ssh") != ":2200" {
		t.Errorf("TrapAddr(ssh) = %q, want :2200", c.TrapAddr("ssh"))
	}
}

func TestCrowdSecEnabled(t *testing.T) {
	c, err := Load(envFunc(map[string]string{
		"RAN_TRAPS":            "ssh",
		"RAN_CROWDSEC":         "on",
		"RAN_CROWDSEC_URL":     "http://crowdsec:8080",
		"RAN_CROWDSEC_API_KEY": "abc123",
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
		"RAN_TRAPS":            "ssh",
		"RAN_CROWDSEC":         "on",
		"RAN_CROWDSEC_API_KEY": "abc123",
	}))
	if err == nil {
		t.Fatal("expected error when CrowdSec enabled without URL")
	}
}

func TestCrowdSecMissingKey(t *testing.T) {
	_, err := Load(envFunc(map[string]string{
		"RAN_TRAPS":        "ssh",
		"RAN_CROWDSEC":     "on",
		"RAN_CROWDSEC_URL": "http://crowdsec:8080",
	}))
	if err == nil {
		t.Fatal("expected error when CrowdSec enabled without API key")
	}
}

func TestCrowdSecPermanentBan(t *testing.T) {
	c, err := Load(envFunc(map[string]string{
		"RAN_TRAPS":                 "ssh",
		"RAN_CROWDSEC":              "on",
		"RAN_CROWDSEC_URL":          "http://crowdsec:8080",
		"RAN_CROWDSEC_API_KEY":      "abc123",
		"RAN_CROWDSEC_BAN_DURATION": "0",
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
		"RAN_TRAPS":                 "ssh",
		"RAN_CROWDSEC":              "on",
		"RAN_CROWDSEC_URL":          "http://crowdsec:8080",
		"RAN_CROWDSEC_API_KEY":      "abc123",
		"RAN_CROWDSEC_BAN_DURATION": "24h",
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
		"RAN_TRAPS":        "ssh",
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

func TestRanTrapsList(t *testing.T) {
	c, err := Load(envFunc(map[string]string{
		"RAN_TRAPS": "ssh,ftp,redis",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	traps := c.EnabledTraps()
	if len(traps) != 3 {
		t.Fatalf("EnabledTraps() len = %d, want 3", len(traps))
	}
	if traps[0] != "ssh" || traps[1] != "ftp" || traps[2] != "redis" {
		t.Errorf("EnabledTraps() = %v, want [ssh ftp redis]", traps)
	}
}

func TestRanTrapsUnknownName(t *testing.T) {
	_, err := Load(envFunc(map[string]string{
		"RAN_TRAPS": "ssh,banana",
	}))
	if err == nil {
		t.Fatal("expected error for unknown trap name")
	}
}

func TestTrapAddrDefault(t *testing.T) {
	c, _ := Load(envFunc(map[string]string{"RAN_TRAPS": "ftp"}))
	if c.TrapAddr("ftp") != ":21" {
		t.Errorf("TrapAddr(ftp) = %q, want :21", c.TrapAddr("ftp"))
	}
}

func TestTrapAddrOverride(t *testing.T) {
	c, _ := Load(envFunc(map[string]string{
		"RAN_TRAPS":    "ftp",
		"RAN_FTP_ADDR": ":2121",
	}))
	if c.TrapAddr("ftp") != ":2121" {
		t.Errorf("TrapAddr(ftp) = %q, want :2121", c.TrapAddr("ftp"))
	}
}
