package config

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

type Config struct {
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

func Load(getenv func(string) string) (*Config, error) {
	e := &envReader{getenv: getenv}
	c := &Config{
		SSH:            e.boolean("RAN_SSH", false),
		HTTP:           e.boolean("RAN_HTTP", false),
		MySQL:          e.boolean("RAN_MYSQL", false),
		SSHAddr:        e.str("RAN_SSH_ADDR", ":2222"),
		HTTPAddr:       e.str("RAN_HTTP_ADDR", ":8081"),
		MySQLAddr:      e.str("RAN_MYSQL_ADDR", ":3307"),
		LogLevel:       e.logLevel("RAN_LOG_LEVEL", slog.LevelInfo),
		LogFormat:      e.logFormat("RAN_LOG_FORMAT", "json"),
		MetricsAddr:    e.str("RAN_METRICS_ADDR", ":9550"),
		SessionTimeout: e.duration("RAN_SESSION_TIMEOUT", 30*time.Second),
		MaxSessions:    e.intMin("RAN_MAX_SESSIONS", 500, 1),
		MaxPerIP:            e.intMin("RAN_MAX_PER_IP", 10, 1),
		CrowdSec:            e.boolean("RAN_CROWDSEC", false),
		CrowdSecURL:         e.str("RAN_CROWDSEC_URL", ""),
		CrowdSecAPIKey:      e.str("RAN_CROWDSEC_API_KEY", ""),
		CrowdSecBanDuration: e.banDuration("RAN_CROWDSEC_BAN_DURATION", 4*time.Hour),
	}
	if e.err != nil {
		return nil, e.err
	}
	if !c.SSH && !c.HTTP && !c.MySQL {
		return nil, fmt.Errorf("at least one trap must be enabled (RAN_SSH, RAN_HTTP, or RAN_MYSQL)")
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
