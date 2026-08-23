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
		"RAN_TRAPS":               "ssh",
		"RAN_CROWDSEC":            "on",
		"RAN_CROWDSEC_URL":        "http://crowdsec:8080",
		"RAN_CROWDSEC_MACHINE_ID": "ran-honeypot",
		"RAN_CROWDSEC_PASSWORD":   "secret",
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
		"RAN_TRAPS":               "ssh",
		"RAN_CROWDSEC":            "on",
		"RAN_CROWDSEC_MACHINE_ID": "ran-honeypot",
		"RAN_CROWDSEC_PASSWORD":   "secret",
	}))
	if err == nil {
		t.Fatal("expected error when CrowdSec enabled without URL")
	}
}

func TestCrowdSecMissingMachineID(t *testing.T) {
	_, err := Load(envFunc(map[string]string{
		"RAN_TRAPS":             "ssh",
		"RAN_CROWDSEC":          "on",
		"RAN_CROWDSEC_URL":      "http://crowdsec:8080",
		"RAN_CROWDSEC_PASSWORD": "secret",
	}))
	if err == nil {
		t.Fatal("expected error when CrowdSec enabled without machine ID")
	}
}

func TestCrowdSecMissingPassword(t *testing.T) {
	_, err := Load(envFunc(map[string]string{
		"RAN_TRAPS":               "ssh",
		"RAN_CROWDSEC":            "on",
		"RAN_CROWDSEC_URL":        "http://crowdsec:8080",
		"RAN_CROWDSEC_MACHINE_ID": "ran-honeypot",
	}))
	if err == nil {
		t.Fatal("expected error when CrowdSec enabled without password")
	}
}

func TestCrowdSecPermanentBan(t *testing.T) {
	c, err := Load(envFunc(map[string]string{
		"RAN_TRAPS":                 "ssh",
		"RAN_CROWDSEC":              "on",
		"RAN_CROWDSEC_URL":          "http://crowdsec:8080",
		"RAN_CROWDSEC_MACHINE_ID":   "ran-honeypot",
		"RAN_CROWDSEC_PASSWORD":     "secret",
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
		"RAN_CROWDSEC_MACHINE_ID":   "ran-honeypot",
		"RAN_CROWDSEC_PASSWORD":     "secret",
		"RAN_CROWDSEC_BAN_DURATION": "24h",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.CrowdSecBanDuration != 24*time.Hour {
		t.Errorf("CrowdSecBanDuration = %v, want 24h", c.CrowdSecBanDuration)
	}
}

func TestCrowdSecOptimizationDefaults(t *testing.T) {
	c, err := Load(envFunc(map[string]string{
		"RAN_TRAPS":               "ssh",
		"RAN_CROWDSEC":            "on",
		"RAN_CROWDSEC_URL":        "http://crowdsec:8080",
		"RAN_CROWDSEC_MACHINE_ID": "ran",
		"RAN_CROWDSEC_PASSWORD":   "secret",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.CrowdSecDedupWindow != 5*time.Minute {
		t.Errorf("CrowdSecDedupWindow = %v, want 5m", c.CrowdSecDedupWindow)
	}
	if c.CrowdSecBatchInterval != 10*time.Second {
		t.Errorf("CrowdSecBatchInterval = %v, want 10s", c.CrowdSecBatchInterval)
	}
	if c.CrowdSecBatchSize != 50 {
		t.Errorf("CrowdSecBatchSize = %d, want 50", c.CrowdSecBatchSize)
	}
	if !c.CrowdSecDecisionCache {
		t.Error("CrowdSecDecisionCache should default to true")
	}
}

func TestCrowdSecOptimizationCustom(t *testing.T) {
	c, err := Load(envFunc(map[string]string{
		"RAN_TRAPS":                   "ssh",
		"RAN_CROWDSEC":                "on",
		"RAN_CROWDSEC_URL":            "http://crowdsec:8080",
		"RAN_CROWDSEC_MACHINE_ID":     "ran",
		"RAN_CROWDSEC_PASSWORD":       "secret",
		"RAN_CROWDSEC_DEDUP_WINDOW":   "10m",
		"RAN_CROWDSEC_BATCH_INTERVAL": "30s",
		"RAN_CROWDSEC_BATCH_SIZE":     "100",
		"RAN_CROWDSEC_DECISION_CACHE": "off",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.CrowdSecDedupWindow != 10*time.Minute {
		t.Errorf("CrowdSecDedupWindow = %v, want 10m", c.CrowdSecDedupWindow)
	}
	if c.CrowdSecBatchInterval != 30*time.Second {
		t.Errorf("CrowdSecBatchInterval = %v, want 30s", c.CrowdSecBatchInterval)
	}
	if c.CrowdSecBatchSize != 100 {
		t.Errorf("CrowdSecBatchSize = %d, want 100", c.CrowdSecBatchSize)
	}
	if c.CrowdSecDecisionCache {
		t.Error("CrowdSecDecisionCache should be false")
	}
}

func TestCrowdSecDedupWindowDisabled(t *testing.T) {
	c, err := Load(envFunc(map[string]string{
		"RAN_TRAPS":                 "ssh",
		"RAN_CROWDSEC_DEDUP_WINDOW": "0s",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.CrowdSecDedupWindow != 0 {
		t.Errorf("CrowdSecDedupWindow = %v, want 0", c.CrowdSecDedupWindow)
	}
}

func TestCrowdSecBatchIntervalDisabled(t *testing.T) {
	c, err := Load(envFunc(map[string]string{
		"RAN_TRAPS":                   "ssh",
		"RAN_CROWDSEC_BATCH_INTERVAL": "0s",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.CrowdSecBatchInterval != 0 {
		t.Errorf("CrowdSecBatchInterval = %v, want 0", c.CrowdSecBatchInterval)
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

func TestTrapAddrsSingle(t *testing.T) {
	c, _ := Load(envFunc(map[string]string{"RAN_TRAPS": "ssh"}))
	addrs := c.TrapAddrs("ssh")
	if len(addrs) != 1 || addrs[0] != ":2222" {
		t.Errorf("TrapAddrs(ssh) = %v, want [:2222]", addrs)
	}
}

func TestTrapAddrsMultiple(t *testing.T) {
	c, _ := Load(envFunc(map[string]string{
		"RAN_TRAPS":     "http",
		"RAN_HTTP_ADDR": ":8081,:8080,:8443",
	}))
	addrs := c.TrapAddrs("http")
	if len(addrs) != 3 || addrs[0] != ":8081" || addrs[1] != ":8080" || addrs[2] != ":8443" {
		t.Errorf("TrapAddrs(http) = %v, want [:8081 :8080 :8443]", addrs)
	}
}

func TestTrapAddrsWhitespace(t *testing.T) {
	c, _ := Load(envFunc(map[string]string{
		"RAN_TRAPS":     "http",
		"RAN_HTTP_ADDR": ":8081, :8080 , :8443",
	}))
	addrs := c.TrapAddrs("http")
	if len(addrs) != 3 || addrs[0] != ":8081" || addrs[1] != ":8080" || addrs[2] != ":8443" {
		t.Errorf("TrapAddrs(http) = %v, want [:8081 :8080 :8443]", addrs)
	}
}

func TestTrapAddrsUnknown(t *testing.T) {
	c, _ := Load(envFunc(map[string]string{"RAN_TRAPS": "ssh"}))
	addrs := c.TrapAddrs("unknown")
	if addrs != nil {
		t.Errorf("TrapAddrs(unknown) = %v, want nil", addrs)
	}
}

func TestADBTrapValid(t *testing.T) {
	c, err := Load(envFunc(map[string]string{"RAN_TRAPS": "adb"}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.TrapAddr("adb") != ":5555" {
		t.Errorf("TrapAddr(adb) = %q, want :5555", c.TrapAddr("adb"))
	}
}

func TestMinecraftTrapValid(t *testing.T) {
	c, err := Load(envFunc(map[string]string{"RAN_TRAPS": "minecraft"}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.TrapAddr("minecraft") != ":25565" {
		t.Errorf("TrapAddr(minecraft) = %q, want :25565", c.TrapAddr("minecraft"))
	}
}

func TestMaxAuthRetriesDefault(t *testing.T) {
	c, _ := Load(envFunc(map[string]string{"RAN_TRAPS": "ssh"}))
	if c.MaxAuthRetries != 3 {
		t.Errorf("MaxAuthRetries = %d, want 3", c.MaxAuthRetries)
	}
	if c.ResolveMaxAuthRetries("ssh") != 3 {
		t.Errorf("ResolveMaxAuthRetries(ssh) = %d, want 3", c.ResolveMaxAuthRetries("ssh"))
	}
}

func TestMaxAuthRetriesGlobal(t *testing.T) {
	c, _ := Load(envFunc(map[string]string{
		"RAN_TRAPS":            "ssh",
		"RAN_MAX_AUTH_RETRIES": "5",
	}))
	if c.ResolveMaxAuthRetries("ssh") != 5 {
		t.Errorf("ResolveMaxAuthRetries(ssh) = %d, want 5", c.ResolveMaxAuthRetries("ssh"))
	}
}

func TestMaxAuthRetriesPerProto(t *testing.T) {
	c, _ := Load(envFunc(map[string]string{
		"RAN_TRAPS":                  "ssh,telnet",
		"RAN_MAX_AUTH_RETRIES":       "3",
		"RAN_SSH_MAX_AUTH_RETRIES":   "6",
	}))
	if c.ResolveMaxAuthRetries("ssh") != 6 {
		t.Errorf("ResolveMaxAuthRetries(ssh) = %d, want 6", c.ResolveMaxAuthRetries("ssh"))
	}
	if c.ResolveMaxAuthRetries("telnet") != 3 {
		t.Errorf("ResolveMaxAuthRetries(telnet) = %d, want 3", c.ResolveMaxAuthRetries("telnet"))
	}
}

func TestMaxAuthRetriesUnlimited(t *testing.T) {
	c, _ := Load(envFunc(map[string]string{
		"RAN_TRAPS":                    "mssql",
		"RAN_MSSQL_MAX_AUTH_RETRIES":   "0",
	}))
	if c.ResolveMaxAuthRetries("mssql") != 0 {
		t.Errorf("ResolveMaxAuthRetries(mssql) = %d, want 0", c.ResolveMaxAuthRetries("mssql"))
	}
}

func TestMaxAuthRetriesInvalid(t *testing.T) {
	_, err := Load(envFunc(map[string]string{
		"RAN_TRAPS":            "ssh",
		"RAN_MAX_AUTH_RETRIES": "banana",
	}))
	if err == nil {
		t.Fatal("expected error for invalid max auth retries")
	}
}

func TestMaxAuthRetriesPerProtoInvalid(t *testing.T) {
	_, err := Load(envFunc(map[string]string{
		"RAN_TRAPS":                 "ssh",
		"RAN_SSH_MAX_AUTH_RETRIES":  "-1",
	}))
	if err == nil {
		t.Fatal("expected error for negative per-proto max auth retries")
	}
}

func TestAuthDelayDefault(t *testing.T) {
	c, _ := Load(envFunc(map[string]string{"RAN_TRAPS": "ssh"}))
	if c.AuthDelay != 0 {
		t.Errorf("AuthDelay = %v, want 0", c.AuthDelay)
	}
	if c.ResolveAuthDelay("ssh") != 0 {
		t.Errorf("ResolveAuthDelay(ssh) = %v, want 0", c.ResolveAuthDelay("ssh"))
	}
}

func TestAuthDelayPerProto(t *testing.T) {
	c, _ := Load(envFunc(map[string]string{
		"RAN_TRAPS":          "ssh,telnet",
		"RAN_AUTH_DELAY":     "1s",
		"RAN_SSH_AUTH_DELAY": "3s",
	}))
	if c.ResolveAuthDelay("ssh") != 3*time.Second {
		t.Errorf("ResolveAuthDelay(ssh) = %v, want 3s", c.ResolveAuthDelay("ssh"))
	}
	if c.ResolveAuthDelay("telnet") != 1*time.Second {
		t.Errorf("ResolveAuthDelay(telnet) = %v, want 1s", c.ResolveAuthDelay("telnet"))
	}
}

func TestAuthDelayInvalid(t *testing.T) {
	_, err := Load(envFunc(map[string]string{
		"RAN_TRAPS":          "ssh",
		"RAN_SSH_AUTH_DELAY": "notaduration",
	}))
	if err == nil {
		t.Fatal("expected error for invalid per-proto auth delay")
	}
}

func TestSSHTarpitDefault(t *testing.T) {
	c, _ := Load(envFunc(map[string]string{"RAN_TRAPS": "ssh"}))
	if c.SSHTarpit {
		t.Error("SSHTarpit should default to false")
	}
	if c.SSHTarpitDuration != 30*time.Second {
		t.Errorf("SSHTarpitDuration = %v, want 30s", c.SSHTarpitDuration)
	}
}

func TestSSHTarpitEnabled(t *testing.T) {
	c, _ := Load(envFunc(map[string]string{
		"RAN_TRAPS":               "ssh",
		"RAN_SSH_TARPIT":          "on",
		"RAN_SSH_TARPIT_DURATION": "1m",
	}))
	if !c.SSHTarpit {
		t.Error("SSHTarpit should be true")
	}
	if c.SSHTarpitDuration != time.Minute {
		t.Errorf("SSHTarpitDuration = %v, want 1m", c.SSHTarpitDuration)
	}
}

func TestPerProtoSessionTimeout(t *testing.T) {
	c, _ := Load(envFunc(map[string]string{
		"RAN_TRAPS":               "ssh,telnet",
		"RAN_SESSION_TIMEOUT":     "30s",
		"RAN_SSH_SESSION_TIMEOUT": "120s",
	}))
	if c.ResolveSessionTimeout("ssh") != 120*time.Second {
		t.Errorf("ResolveSessionTimeout(ssh) = %v, want 120s", c.ResolveSessionTimeout("ssh"))
	}
	if c.ResolveSessionTimeout("telnet") != 30*time.Second {
		t.Errorf("ResolveSessionTimeout(telnet) = %v, want 30s", c.ResolveSessionTimeout("telnet"))
	}
}

func TestPerProtoSessionTimeoutInvalid(t *testing.T) {
	_, err := Load(envFunc(map[string]string{
		"RAN_TRAPS":               "ssh",
		"RAN_SSH_SESSION_TIMEOUT": "notvalid",
	}))
	if err == nil {
		t.Fatal("expected error for invalid per-proto session timeout")
	}
}
