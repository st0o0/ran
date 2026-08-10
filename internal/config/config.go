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

	// Legacy fields kept for backwards compat in run.go migration
	SSH   bool
	HTTP  bool
	MySQL bool

	SSHAddr   string
	HTTPAddr  string
	MySQLAddr string

	LogLevel  slog.Level
	LogFormat string

	MetricsAddr string

	SessionTimeout time.Duration
	MaxSessions    int
	MaxPerIP       int

	CrowdSec            bool
	CrowdSecURL         string
	CrowdSecAPIKey      string
	CrowdSecBanDuration time.Duration
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

func Load(getenv func(string) string) (*Config, error) {
	e := &envReader{getenv: getenv}

	c := &Config{
		Addrs:          make(map[string]string),
		LogLevel:       e.logLevel("RAN_LOG_LEVEL", slog.LevelInfo),
		LogFormat:      e.logFormat("RAN_LOG_FORMAT", "json"),
		MetricsAddr:    e.str("RAN_METRICS_ADDR", ":9550"),
		SessionTimeout: e.duration("RAN_SESSION_TIMEOUT", 30*time.Second),
		MaxSessions:    e.intMin("RAN_MAX_SESSIONS", 500, 1),
		MaxPerIP:       e.intMin("RAN_MAX_PER_IP", 10, 1),
		CrowdSec:       e.boolean("RAN_CROWDSEC", false),
		CrowdSecURL:    e.str("RAN_CROWDSEC_URL", ""),
		CrowdSecAPIKey: e.str("RAN_CROWDSEC_API_KEY", ""),
		CrowdSecBanDuration: e.banDuration("RAN_CROWDSEC_BAN_DURATION", 4*time.Hour),
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
	} else {
		// Legacy per-trap env vars
		legacySSH := e.boolean("RAN_SSH", false)
		legacyHTTP := e.boolean("RAN_HTTP", false)
		legacyMySQL := e.boolean("RAN_MYSQL", false)
		if e.err != nil {
			return nil, e.err
		}
		if legacySSH {
			c.Traps = append(c.Traps, "ssh")
		}
		if legacyHTTP {
			c.Traps = append(c.Traps, "http")
		}
		if legacyMySQL {
			c.Traps = append(c.Traps, "mysql")
		}
	}

	if len(c.Traps) == 0 {
		return nil, fmt.Errorf("at least one trap must be enabled (RAN_TRAPS or RAN_SSH, RAN_HTTP, RAN_MYSQL)")
	}

	// Set legacy bool fields for backwards compat
	for _, name := range c.Traps {
		switch name {
		case "ssh":
			c.SSH = true
		case "http":
			c.HTTP = true
		case "mysql":
			c.MySQL = true
		}
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

	// Keep legacy addr fields in sync
	c.SSHAddr = c.TrapAddr("ssh")
	c.HTTPAddr = c.TrapAddr("http")
	c.MySQLAddr = c.TrapAddr("mysql")
	if c.SSHAddr == "" {
		c.SSHAddr = DefaultPorts["ssh"]
	}
	if c.HTTPAddr == "" {
		c.HTTPAddr = DefaultPorts["http"]
	}
	if c.MySQLAddr == "" {
		c.MySQLAddr = DefaultPorts["mysql"]
	}

	if c.CrowdSec {
		if c.CrowdSecURL == "" {
			return nil, fmt.Errorf("RAN_CROWDSEC_URL is required when RAN_CROWDSEC=on")
		}
		if c.CrowdSecAPIKey == "" {
			return nil, fmt.Errorf("RAN_CROWDSEC_API_KEY is required when RAN_CROWDSEC=on")
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
