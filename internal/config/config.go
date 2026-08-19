package config

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

var DefaultPorts = map[string]string{
	"ssh":           ":2222",
	"http":          ":8081",
	"mysql":         ":3307",
	"ftp":           ":21",
	"telnet":        ":23",
	"smtp":          ":25",
	"dns":           ":53",
	"pop3":          ":110",
	"imap":          ":143",
	"ldap":          ":389",
	"smb":           ":445",
	"modbus":        ":502",
	"socks5":        ":1080",
	"mssql":         ":1433",
	"oracle":        ":1521",
	"mqtt":          ":1883",
	"rdp":           ":3389",
	"postgres":      ":5432",
	"sip":           ":5060",
	"vnc":           ":5900",
	"redis":         ":6379",
	"irc":           ":6667",
	"httpproxy":     ":8080",
	"elasticsearch": ":9200",
	"ntp":           ":123",
	"snmp":          ":161",
	"memcached":     ":11211",
	"adb":           ":5555",
	"minecraft":     ":25565",
}

var ValidTraps = func() map[string]bool {
	m := make(map[string]bool, len(DefaultPorts))
	for k := range DefaultPorts {
		m[k] = true
	}
	return m
}()

type Config struct {
	Traps []string
	Addrs map[string]string

	SSHHostKeyPath string

	LogLevel  slog.Level
	LogFormat string

	MetricsAddr string

	SessionTimeout time.Duration
	MaxSessions    int
	MaxPerIP       int

	ProxyProtocol bool

	CrowdSec              bool
	CrowdSecURL           string
	CrowdSecMachineID     string
	CrowdSecPassword      string
	CrowdSecBanDuration   time.Duration
	CrowdSecDedupWindow   time.Duration
	CrowdSecBatchInterval time.Duration
	CrowdSecBatchSize     int
	CrowdSecDecisionCache bool
}

func (c *Config) EnabledTraps() []string {
	return c.Traps
}

func (c *Config) TrapAddr(name string) string {
	if addr, ok := c.Addrs[name]; ok {
		return addr
	}
	if def, ok := DefaultPorts[name]; ok {
		return def
	}
	return ""
}

func (c *Config) TrapAddrs(name string) []string {
	raw := c.TrapAddr(name)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	addrs := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			addrs = append(addrs, s)
		}
	}
	return addrs
}

func Load(getenv func(string) string) (*Config, error) {
	e := &envReader{getenv: getenv}

	c := &Config{
		Addrs:               make(map[string]string),
		SSHHostKeyPath:      e.str("RAN_SSH_HOST_KEY_PATH", "/data/ssh_host_key"),
		LogLevel:            e.logLevel("RAN_LOG_LEVEL", slog.LevelInfo),
		LogFormat:           e.logFormat("RAN_LOG_FORMAT", "json"),
		MetricsAddr:         e.str("RAN_METRICS_ADDR", ":9550"),
		SessionTimeout:      e.duration("RAN_SESSION_TIMEOUT", 30*time.Second),
		MaxSessions:         e.intMin("RAN_MAX_SESSIONS", 500, 1),
		MaxPerIP:            e.intMin("RAN_MAX_PER_IP", 10, 1),
		ProxyProtocol:       e.boolean("RAN_PROXY_PROTOCOL", false),
		CrowdSec:            e.boolean("RAN_CROWDSEC", false),
		CrowdSecURL:         e.str("RAN_CROWDSEC_URL", ""),
		CrowdSecMachineID:   e.str("RAN_CROWDSEC_MACHINE_ID", ""),
		CrowdSecPassword:    e.str("RAN_CROWDSEC_PASSWORD", ""),
		CrowdSecBanDuration:   e.banDuration("RAN_CROWDSEC_BAN_DURATION", 4*time.Hour),
		CrowdSecDedupWindow:   e.duration("RAN_CROWDSEC_DEDUP_WINDOW", 5*time.Minute),
		CrowdSecBatchInterval: e.duration("RAN_CROWDSEC_BATCH_INTERVAL", 10*time.Second),
		CrowdSecBatchSize:     e.intMin("RAN_CROWDSEC_BATCH_SIZE", 50, 1),
		CrowdSecDecisionCache: e.boolean("RAN_CROWDSEC_DECISION_CACHE", true),
	}
	if e.err != nil {
		return nil, e.err
	}

	// Parse trap list
	trapList := strings.TrimSpace(getenv("RAN_TRAPS"))
	if trapList != "" {
		for _, name := range strings.Split(trapList, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			if !ValidTraps[name] {
				validNames := make([]string, 0, len(ValidTraps))
				for k := range ValidTraps {
					validNames = append(validNames, k)
				}
				return nil, fmt.Errorf("unknown trap %q in RAN_TRAPS (valid: %s)", name, strings.Join(validNames, ", "))
			}
			c.Traps = append(c.Traps, name)
		}
	}

	if len(c.Traps) == 0 {
		return nil, fmt.Errorf("at least one trap must be enabled via RAN_TRAPS")
	}

	// Load per-trap addr overrides
	for _, name := range c.Traps {
		envKey := "RAN_" + strings.ToUpper(name) + "_ADDR"
		if addr := getenv(envKey); addr != "" {
			c.Addrs[name] = addr
		} else {
			c.Addrs[name] = DefaultPorts[name]
		}
	}

	if c.CrowdSec {
		if c.CrowdSecURL == "" {
			return nil, fmt.Errorf("RAN_CROWDSEC_URL is required when RAN_CROWDSEC=on")
		}
		if c.CrowdSecMachineID == "" {
			return nil, fmt.Errorf("RAN_CROWDSEC_MACHINE_ID is required when RAN_CROWDSEC=on")
		}
		if c.CrowdSecPassword == "" {
			return nil, fmt.Errorf("RAN_CROWDSEC_PASSWORD is required when RAN_CROWDSEC=on")
		}
	}
	return c, nil
}

type envReader struct {
	getenv func(string) string
	err    error
}

func (e *envReader) str(name, def string) string {
	if v := e.getenv(name); v != "" {
		return v
	}
	return def
}

func (e *envReader) intMin(name string, def, min int) int {
	v := strings.TrimSpace(e.getenv(name))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min {
		e.setErr(fmt.Errorf("%s must be an integer >= %d, got %q", name, min, v))
		return def
	}
	return n
}

func (e *envReader) duration(name string, def time.Duration) time.Duration {
	v := strings.TrimSpace(e.getenv(name))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		e.setErr(fmt.Errorf("%s must be a valid Go duration, got %q", name, v))
		return def
	}
	return d
}

func (e *envReader) banDuration(name string, def time.Duration) time.Duration {
	v := strings.TrimSpace(e.getenv(name))
	if v == "" {
		return def
	}
	if v == "0" {
		return 0
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		e.setErr(fmt.Errorf("%s must be a valid Go duration or 0, got %q", name, v))
		return def
	}
	return d
}

func (e *envReader) boolean(name string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(e.getenv(name))) {
	case "":
		return def
	case "on", "true", "yes", "1":
		return true
	case "off", "false", "no", "0":
		return false
	default:
		e.setErr(fmt.Errorf("%s must be on/off, got %q", name, e.getenv(name)))
		return def
	}
}

func (e *envReader) logLevel(name string, def slog.Level) slog.Level {
	switch strings.ToLower(strings.TrimSpace(e.getenv(name))) {
	case "", "info":
		return slog.LevelInfo
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		e.setErr(fmt.Errorf("%s must be debug/info/warn/error, got %q", name, e.getenv(name)))
		return def
	}
}

func (e *envReader) logFormat(name, def string) string {
	switch strings.ToLower(strings.TrimSpace(e.getenv(name))) {
	case "":
		return def
	case "json", "text":
		return strings.ToLower(strings.TrimSpace(e.getenv(name)))
	default:
		e.setErr(fmt.Errorf("%s must be json/text, got %q", name, e.getenv(name)))
		return def
	}
}

func (e *envReader) setErr(err error) {
	if e.err == nil {
		e.err = err
	}
}
