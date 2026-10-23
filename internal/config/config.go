package config

import (
	"fmt"
	"log/slog"
	"net"
	"sort"
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

// ValidClasses are the session classes accepted by RAN_BAN_ON.
var ValidClasses = map[string]bool{"probe": true, "attack": true, "scan": true}

// RemovedEnvVars are variables removed in 0.4.0. They are ignored; a warning is
// logged once when one is still set.
var RemovedEnvVars = []string{
	"RAN_CROWDSEC_BAN_DURATION",
	"RAN_CROWDSEC_DECISION_CACHE",
	"RAN_CROWDSEC_DEDUP_WINDOW",
}

type ProtoConfig struct {
	MaxAuthRetries *int
	AuthDelay      *time.Duration
	SessionTimeout *time.Duration
}

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

	MaxAuthRetries    int
	AuthDelay         time.Duration
	SSHTarpit         bool
	SSHTarpitDuration time.Duration

	PerProto map[string]ProtoConfig

	ProxyProtocol bool

	CrowdSec              bool
	CrowdSecURL           string
	CrowdSecMachineID     string
	CrowdSecPassword      string
	CrowdSecBatchInterval time.Duration
	CrowdSecBatchSize     int
	CrowdSecMaxTracked    int

	// BanOn lists the classes (probe, attack, scan) that produce a CrowdSec alert.
	BanOn []string
	// AlertCooldown allows at most one alert per IP and class per window (0 = off).
	AlertCooldown time.Duration
	// ProbeSummaryWindow is the probe log aggregation window (0 = per-session lines).
	ProbeSummaryWindow time.Duration

	// RemovedEnvVars lists removed variables still set in the environment, so
	// the caller can warn once.
	RemovedEnvVars []string

	LogPasswords string

	UDPRatePerSource int
	UDPRateBurst     int
	UDPRateGlobal    int
}

// ValidTrapNames returns the valid RAN_TRAPS names in sorted order.
func ValidTrapNames() []string {
	names := make([]string, 0, len(ValidTraps))
	for k := range ValidTraps {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// ValidateAddrList checks a comma-separated list of listen addresses (host:port
// or :port). name is the environment variable, used in the error message.
func ValidateAddrList(name, raw string) error {
	n := 0
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n++
		_, port, err := net.SplitHostPort(part)
		if err != nil {
			return fmt.Errorf("%s has an invalid listen address %q (%v); use host:port or :port, for example :2222 or 0.0.0.0:2222,[::]:2222", name, part, err)
		}
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("%s has an invalid port in %q; use a port between 1 and 65535", name, part)
		}
	}
	if n == 0 {
		return fmt.Errorf("%s must contain at least one listen address such as :2222", name)
	}
	return nil
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

func (c *Config) ResolveMaxAuthRetries(proto string) int {
	if pc, ok := c.PerProto[proto]; ok && pc.MaxAuthRetries != nil {
		return *pc.MaxAuthRetries
	}
	return c.MaxAuthRetries
}

func (c *Config) ResolveAuthDelay(proto string) time.Duration {
	if pc, ok := c.PerProto[proto]; ok && pc.AuthDelay != nil {
		return *pc.AuthDelay
	}
	return c.AuthDelay
}

func (c *Config) ResolveSessionTimeout(proto string) time.Duration {
	if pc, ok := c.PerProto[proto]; ok && pc.SessionTimeout != nil {
		return *pc.SessionTimeout
	}
	return c.SessionTimeout
}

func Load(getenv func(string) string) (*Config, error) {
	e := &envReader{getenv: getenv}

	c := &Config{
		Addrs:                 make(map[string]string),
		PerProto:              make(map[string]ProtoConfig),
		SSHHostKeyPath:        e.str("RAN_SSH_HOST_KEY_PATH", "/data/ssh_host_key"),
		LogLevel:              e.logLevel("RAN_LOG_LEVEL", slog.LevelInfo),
		LogFormat:             e.logFormat("RAN_LOG_FORMAT", "json"),
		MetricsAddr:           e.str("RAN_METRICS_ADDR", ":9550"),
		SessionTimeout:        e.duration("RAN_SESSION_TIMEOUT", 30*time.Second),
		MaxSessions:           e.intMin("RAN_MAX_SESSIONS", 500, 1),
		MaxPerIP:              e.intMin("RAN_MAX_PER_IP", 10, 1),
		MaxAuthRetries:        e.intMin("RAN_MAX_AUTH_RETRIES", 3, 0),
		AuthDelay:             e.duration("RAN_AUTH_DELAY", 0),
		SSHTarpit:             e.boolean("RAN_SSH_TARPIT", false),
		SSHTarpitDuration:     e.duration("RAN_SSH_TARPIT_DURATION", 30*time.Second),
		ProxyProtocol:         e.boolean("RAN_PROXY_PROTOCOL", false),
		CrowdSec:              e.boolean("RAN_CROWDSEC", false),
		CrowdSecURL:           e.str("RAN_CROWDSEC_URL", ""),
		CrowdSecMachineID:     e.str("RAN_CROWDSEC_MACHINE_ID", ""),
		CrowdSecPassword:      e.str("RAN_CROWDSEC_PASSWORD", ""),
		CrowdSecBatchInterval: e.duration("RAN_CROWDSEC_BATCH_INTERVAL", 10*time.Second),
		CrowdSecBatchSize:     e.intMin("RAN_CROWDSEC_BATCH_SIZE", 50, 1),
		CrowdSecMaxTracked:    e.intMin("RAN_CROWDSEC_MAX_TRACKED", 20000, 1),
		BanOn:                 e.classes("RAN_BAN_ON", []string{"attack", "scan"}),
		AlertCooldown:         e.durationMin0("RAN_ALERT_COOLDOWN", 4*time.Hour),
		ProbeSummaryWindow:    e.durationMin0("RAN_PROBE_SUMMARY_WINDOW", 60*time.Second),
		LogPasswords:          e.logPasswords("RAN_LOG_PASSWORDS", "off"),
		UDPRatePerSource:      e.intMin("RAN_UDP_RATE_PER_SOURCE", 20, 1),
		UDPRateBurst:          e.intMin("RAN_UDP_RATE_BURST", 40, 1),
		UDPRateGlobal:         e.intMin("RAN_UDP_RATE_GLOBAL", 2000, 1),
	}
	if e.err != nil {
		return nil, e.err
	}
	if err := ValidateAddrList("RAN_METRICS_ADDR", c.MetricsAddr); err != nil {
		return nil, err
	}
	for _, name := range RemovedEnvVars {
		if strings.TrimSpace(getenv(name)) != "" {
			c.RemovedEnvVars = append(c.RemovedEnvVars, name)
		}
	}
	if c.UDPRateBurst < c.UDPRatePerSource {
		return nil, fmt.Errorf("RAN_UDP_RATE_BURST (%d) must not be smaller than RAN_UDP_RATE_PER_SOURCE (%d); raise the burst or lower the per-source rate", c.UDPRateBurst, c.UDPRatePerSource)
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
				return nil, fmt.Errorf("unknown trap %q in RAN_TRAPS; remove it or use one of: %s", name, strings.Join(ValidTrapNames(), ", "))
			}
			c.Traps = append(c.Traps, name)
		}
	}

	if len(c.Traps) == 0 {
		return nil, fmt.Errorf("at least one trap must be enabled; set RAN_TRAPS to a comma-separated list such as ssh,http,ftp (valid: %s)", strings.Join(ValidTrapNames(), ", "))
	}

	// Load per-trap addr overrides
	for _, name := range c.Traps {
		envKey := "RAN_" + strings.ToUpper(name) + "_ADDR"
		if addr := getenv(envKey); addr != "" {
			if err := ValidateAddrList(envKey, addr); err != nil {
				return nil, err
			}
			c.Addrs[name] = addr
		} else {
			c.Addrs[name] = DefaultPorts[name]
		}
	}

	// Load per-protocol config overrides
	for _, name := range c.Traps {
		upper := strings.ToUpper(name)
		pc := ProtoConfig{}
		if v := strings.TrimSpace(getenv("RAN_" + upper + "_MAX_AUTH_RETRIES")); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return nil, fmt.Errorf("RAN_%s_MAX_AUTH_RETRIES must be an integer >= 0, got %q; set a whole number or unset it", upper, v)
			}
			pc.MaxAuthRetries = &n
		}
		if v := strings.TrimSpace(getenv("RAN_" + upper + "_AUTH_DELAY")); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				return nil, fmt.Errorf("RAN_%s_AUTH_DELAY must be a valid Go duration, got %q; use a value such as 500ms or 30s", upper, v)
			}
			pc.AuthDelay = &d
		}
		if v := strings.TrimSpace(getenv("RAN_" + upper + "_SESSION_TIMEOUT")); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				return nil, fmt.Errorf("RAN_%s_SESSION_TIMEOUT must be a valid Go duration, got %q; use a value such as 500ms or 30s", upper, v)
			}
			pc.SessionTimeout = &d
		}
		if pc.MaxAuthRetries != nil || pc.AuthDelay != nil || pc.SessionTimeout != nil {
			c.PerProto[name] = pc
		}
	}

	if c.CrowdSec {
		if c.CrowdSecURL == "" {
			return nil, fmt.Errorf("RAN_CROWDSEC_URL is required when RAN_CROWDSEC=on; set it to the LAPI URL, for example http://crowdsec:8080, or set RAN_CROWDSEC=off")
		}
		if c.CrowdSecMachineID == "" {
			return nil, fmt.Errorf("RAN_CROWDSEC_MACHINE_ID is required when RAN_CROWDSEC=on; register a machine with cscli machines add and set its ID, or set RAN_CROWDSEC=off")
		}
		if c.CrowdSecPassword == "" {
			return nil, fmt.Errorf("RAN_CROWDSEC_PASSWORD is required when RAN_CROWDSEC=on; set the machine password, or set RAN_CROWDSEC=off")
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
		e.setErr(fmt.Errorf("%s must be an integer >= %d, got %q; set a whole number of at least %d or unset it to use the default (%d)", name, min, v, min, def))
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
		e.setErr(fmt.Errorf("%s must be a valid Go duration, got %q; use a value such as 500ms, 30s or 4h", name, v))
		return def
	}
	return d
}

// durationMin0 is like duration but rejects negative values; 0 disables the feature.
func (e *envReader) durationMin0(name string, def time.Duration) time.Duration {
	d := e.duration(name, def)
	if d < 0 {
		e.setErr(fmt.Errorf("%s must not be negative, got %q; use 0s to disable or a positive duration such as 60s", name, e.getenv(name)))
		return def
	}
	return d
}

// classes parses a comma-separated, non-empty subset of ValidClasses.
func (e *envReader) classes(name string, def []string) []string {
	v := strings.TrimSpace(e.getenv(name))
	if v == "" {
		return def
	}
	var out []string
	seen := map[string]bool{}
	for _, part := range strings.Split(v, ",") {
		c := strings.ToLower(strings.TrimSpace(part))
		if c == "" {
			continue
		}
		if !ValidClasses[c] {
			e.setErr(fmt.Errorf("%s contains invalid class %q (valid: probe, attack, scan); use a comma-separated list such as attack,scan", name, c))
			return def
		}
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		e.setErr(fmt.Errorf("%s must list at least one of probe, attack, scan, got %q; use a comma-separated list such as attack,scan", name, v))
		return def
	}
	return out
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
		e.setErr(fmt.Errorf("%s must be on or off, got %q; use on, off, true, false, yes, no, 1 or 0", name, e.getenv(name)))
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
		e.setErr(fmt.Errorf("%s must be debug, info, warn or error, got %q; set one of these values", name, e.getenv(name)))
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
		e.setErr(fmt.Errorf("%s must be json or text, got %q; set one of these values", name, e.getenv(name)))
		return def
	}
}

func (e *envReader) logPasswords(name, def string) string {
	switch v := strings.ToLower(strings.TrimSpace(e.getenv(name))); v {
	case "":
		return def
	case "off", "mask", "on":
		return v
	default:
		e.setErr(fmt.Errorf("%s must be off, mask or on, got %q; set one of these values", name, e.getenv(name)))
		return def
	}
}

func (e *envReader) setErr(err error) {
	if e.err == nil {
		e.err = err
	}
}
