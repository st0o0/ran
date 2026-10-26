package config_test

import (
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/st0o0/ran/internal/config"
)

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// defaultExtractors formats the Config field behind each non-family setting, so
// the register default can be compared with what Load produces for an empty
// environment. Durations are compared as parsed values (see normalizeDefault).
//
// Two settings are skipped on purpose, see skippedDefaults.
var defaultExtractors = map[string]func(*config.Config) string{
	"RAN_METRICS_ADDR":            func(c *config.Config) string { return c.MetricsAddr },
	"RAN_SSH_HOST_KEY_PATH":       func(c *config.Config) string { return c.SSHHostKeyPath },
	"RAN_HTTPS_CERT_PATH":         func(c *config.Config) string { return c.HTTPSCertPath },
	"RAN_HTTP_FIXTURES":           func(c *config.Config) string { return strconv.Itoa(len(c.HTTPFixtures)) },
	"RAN_FINGERPRINT":             func(c *config.Config) string { return c.FingerprintMode },
	"RAN_FINGERPRINT_SEED_PATH":   func(c *config.Config) string { return c.FingerprintSeedPath },
	"RAN_LOG_LEVEL":               func(c *config.Config) string { return strings.ToLower(c.LogLevel.String()) },
	"RAN_LOG_FORMAT":              func(c *config.Config) string { return c.LogFormat },
	"RAN_LOG_PASSWORDS":           func(c *config.Config) string { return c.LogPasswords },
	"RAN_PROBE_SUMMARY_WINDOW":    func(c *config.Config) string { return c.ProbeSummaryWindow.String() },
	"RAN_SESSION_TIMEOUT":         func(c *config.Config) string { return c.SessionTimeout.String() },
	"RAN_MAX_SESSIONS":            func(c *config.Config) string { return strconv.Itoa(c.MaxSessions) },
	"RAN_MAX_PER_IP":              func(c *config.Config) string { return strconv.Itoa(c.MaxPerIP) },
	"RAN_MAX_AUTH_RETRIES":        func(c *config.Config) string { return strconv.Itoa(c.MaxAuthRetries) },
	"RAN_AUTH_DELAY":              func(c *config.Config) string { return c.AuthDelay.String() },
	"RAN_SSH_TARPIT":              func(c *config.Config) string { return onOff(c.SSHTarpit) },
	"RAN_SSH_TARPIT_DURATION":     func(c *config.Config) string { return c.SSHTarpitDuration.String() },
	"RAN_PROXY_PROTOCOL":          func(c *config.Config) string { return proxyDefault(c) },
	"RAN_PROXY_TRUSTED":           func(c *config.Config) string { return config.FormatPrefixes(c.ProxyTrusted) },
	"RAN_IGNORE_IPS":              func(c *config.Config) string { return config.FormatPrefixes(c.IgnoreIPs) },
	"RAN_UDP_RATE_PER_SOURCE":     func(c *config.Config) string { return strconv.Itoa(c.UDPRatePerSource) },
	"RAN_UDP_RATE_BURST":          func(c *config.Config) string { return strconv.Itoa(c.UDPRateBurst) },
	"RAN_UDP_RATE_GLOBAL":         func(c *config.Config) string { return strconv.Itoa(c.UDPRateGlobal) },
	"RAN_CROWDSEC":                func(c *config.Config) string { return onOff(c.CrowdSec) },
	"RAN_CROWDSEC_URL":            func(c *config.Config) string { return c.CrowdSecURL },
	"RAN_CROWDSEC_MACHINE_ID":     func(c *config.Config) string { return c.CrowdSecMachineID },
	"RAN_CROWDSEC_PASSWORD":       func(c *config.Config) string { return c.CrowdSecPassword },
	"RAN_CROWDSEC_BATCH_INTERVAL": func(c *config.Config) string { return c.CrowdSecBatchInterval.String() },
	"RAN_CROWDSEC_BATCH_SIZE":     func(c *config.Config) string { return strconv.Itoa(c.CrowdSecBatchSize) },
	"RAN_CROWDSEC_MAX_TRACKED":    func(c *config.Config) string { return strconv.Itoa(c.CrowdSecMaxTracked) },
	"RAN_BAN_ON":                  func(c *config.Config) string { return strings.Join(c.BanOn, ",") },
	"RAN_ALERT_COOLDOWN":          func(c *config.Config) string { return c.AlertCooldown.String() },
	"RAN_SHUN":                    func(c *config.Config) string { return onOff(c.Shun) },
	"RAN_REPEAT_AFTER":            func(c *config.Config) string { return strconv.Itoa(c.RepeatAfter) },
	"RAN_REPEAT_COOLDOWN": func(c *config.Config) string {
		if c.RepeatCooldown == 0 {
			return ""
		}
		return c.RepeatCooldown.String()
	},
}

// skippedDefaults cannot be compared against a Config field:
//   - RAN_TRAPS has no default; Load fails without it (covered by the
//     error-no-trap builder case).
//   - RAN_BANNER_SERVICES only fills Config.BannerServices when the banner trap
//     is enabled, and banner has no default services, so there is no field to
//     format for an empty environment.
var skippedDefaults = map[string]bool{
	"RAN_TRAPS":           true,
	"RAN_BANNER_SERVICES": true,
}

func proxyDefault(c *config.Config) string {
	switch {
	case c.ProxyProtocol:
		return "on"
	case len(c.ProxyTraps) > 0:
		return "list"
	}
	return "off"
}

// normalizeDefault renders a register default the way the extractor does.
func normalizeDefault(t *testing.T, s config.Setting) string {
	t.Helper()
	switch s.Name {
	case "RAN_HTTP_FIXTURES":
		return "0"
	case "RAN_LOG_LEVEL":
		if s.Default == "info" {
			return strings.ToLower(slog.LevelInfo.String())
		}
	}
	if s.Kind == config.KindDuration && s.Default != "" {
		d, err := time.ParseDuration(s.Default)
		if err != nil {
			t.Fatalf("%s: default %q is not a duration: %v", s.Name, s.Default, err)
		}
		return d.String()
	}
	return s.Default
}

func familyNames(s config.Setting) []string {
	var out []string
	for _, trap := range s.Traps {
		out = append(out, "RAN_"+strings.ToUpper(trap)+"_"+s.Family)
	}
	return out
}

func TestSettingsMatchLoadedVariables(t *testing.T) {
	registered := map[string]bool{}
	for _, s := range config.Settings {
		if s.Family == "" {
			if registered[s.Name] {
				t.Errorf("duplicate setting %s", s.Name)
			}
			registered[s.Name] = true
			continue
		}
		if !strings.HasPrefix(s.Name, "RAN_<PROTO>_") || s.Name != "RAN_<PROTO>_"+s.Family {
			t.Errorf("family setting %s: name must be RAN_<PROTO>_%s", s.Name, s.Family)
		}
		if len(s.Traps) == 0 {
			t.Errorf("family setting %s lists no traps", s.Name)
		}
		for _, n := range familyNames(s) {
			if registered[n] {
				t.Errorf("duplicate setting %s", n)
			}
			registered[n] = true
		}
		for _, trap := range s.Traps {
			if !config.ValidTraps[trap] {
				t.Errorf("family %s names unknown trap %q", s.Name, trap)
			}
		}
	}

	removed := map[string]bool{}
	for _, v := range config.RemovedEnvVars {
		removed[v] = true
	}
	read := map[string]bool{}
	for _, v := range knownEnvVars(t) {
		read[v] = true
		if removed[v] {
			continue
		}
		if !registered[v] {
			t.Errorf("Load reads %s, which is not in config.Settings", v)
		}
	}
	for name := range registered {
		if !read[name] {
			t.Errorf("config.Settings lists %s, which Load does not read", name)
		}
	}
	for _, s := range config.Settings {
		if removed[s.Name] {
			t.Errorf("config.Settings lists removed variable %s", s.Name)
		}
	}
}

func TestSettingsDefaultsMatchLoad(t *testing.T) {
	c, err := config.Load(func(name string) string {
		if name == "RAN_TRAPS" {
			return "ssh"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range config.Settings {
		if s.Family != "" {
			// Per-trap overrides have no default of their own: unset means
			// inherit the global value. Per-trap listen addresses default to
			// DefaultPorts, checked below.
			if s.Family != "ADDR" && s.Default != "" {
				t.Errorf("%s: a family override must have an empty default, got %q", s.Name, s.Default)
			}
			continue
		}
		if skippedDefaults[s.Name] {
			if s.Default != "" {
				t.Errorf("%s: skipped default must be empty, got %q", s.Name, s.Default)
			}
			continue
		}
		extract, ok := defaultExtractors[s.Name]
		if !ok {
			t.Errorf("%s has no default extractor; add one or list it in skippedDefaults with a reason", s.Name)
			continue
		}
		if got, want := extract(c), normalizeDefault(t, s); got != want {
			t.Errorf("%s: Load default %q, register default %q", s.Name, got, want)
		}
	}
	if len(c.PerProto) != 0 {
		t.Errorf("empty environment produced per-trap overrides: %v", c.PerProto)
	}
	for _, s := range config.Settings {
		if s.Family != "ADDR" {
			continue
		}
		for _, trap := range s.Traps {
			if _, ok := config.DefaultPorts[trap]; !ok && trap != "catchall" {
				t.Errorf("ADDR family lists %s, which has no default port or addressless entry", trap)
			}
		}
		for trap := range config.DefaultPorts {
			if !slices.Contains(s.Traps, trap) {
				t.Errorf("ADDR family misses trap %s", trap)
			}
		}
	}
}

func TestSettingsKindsAreSane(t *testing.T) {
	kinds := []string{config.KindBool, config.KindInt, config.KindDuration, config.KindString, config.KindEnum, config.KindList, config.KindAddr}
	for _, s := range config.Settings {
		if !slices.Contains(kinds, s.Kind) {
			t.Errorf("%s: unknown kind %q", s.Name, s.Kind)
		}
		if s.Group == "" || s.Summary == "" {
			t.Errorf("%s: group and summary are required", s.Name)
		}
		if strings.Contains(s.Summary, "—") || strings.Contains(s.Summary, "–") {
			t.Errorf("%s: summary must not contain dashes beyond --", s.Name)
		}
		if (s.Kind == config.KindEnum) != (len(s.Enum) > 0) {
			t.Errorf("%s: enum values must be given exactly for the enum kind", s.Name)
		}
		if s.Kind == config.KindEnum && s.Default != "" && !slices.Contains(s.Enum, s.Default) {
			t.Errorf("%s: default %q is not one of %v", s.Name, s.Default, s.Enum)
		}
		for _, req := range s.Requires {
			found := false
			for _, o := range config.Settings {
				if o.Name == req {
					found = true
				}
			}
			if !found {
				t.Errorf("%s requires unknown setting %s", s.Name, req)
			}
		}
		switch s.Kind {
		case config.KindBool:
			if s.Default != "on" && s.Default != "off" {
				t.Errorf("%s: bool default must be on or off, got %q", s.Name, s.Default)
			}
		case config.KindInt:
			if s.Default != "" {
				if _, err := strconv.Atoi(s.Default); err != nil {
					t.Errorf("%s: int default %q: %v", s.Name, s.Default, err)
				}
			}
		case config.KindDuration:
			if s.Default != "" {
				if _, err := time.ParseDuration(s.Default); err != nil {
					t.Errorf("%s: duration default %q: %v", s.Name, s.Default, err)
				}
			}
		case config.KindAddr:
			if s.Default != "" {
				if err := config.ValidateAddr(s.Name, s.Default); err != nil {
					t.Errorf("%s: %v", s.Name, err)
				}
			}
		}
	}
}

// TestBuilderCasesReplay runs every shared case through config.Load.
func TestBuilderCasesReplay(t *testing.T) {
	cases := config.BuilderCases()
	if len(cases) == 0 {
		t.Fatal("no builder cases")
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		t.Run(tc.ID, func(t *testing.T) {
			if seen[tc.ID] {
				t.Fatalf("duplicate case id %s", tc.ID)
			}
			seen[tc.ID] = true
			c, err := config.Load(func(name string) string { return tc.Env[name] })
			switch tc.Expect {
			case "error":
				if err == nil {
					t.Fatal("want error, got none")
				}
				if !strings.Contains(err.Error(), tc.MessageContains) {
					t.Errorf("error %q does not contain %q", err, tc.MessageContains)
				}
			case "ok", "warning":
				if err != nil {
					t.Fatalf("want success, got %v", err)
				}
				warnings := c.Warnings()
				if tc.Expect == "ok" && len(warnings) > 0 {
					t.Errorf("want no warning, got %v", warnings)
				}
				if tc.Expect == "warning" {
					if !strings.Contains(strings.Join(warnings, "\n"), tc.MessageContains) {
						t.Errorf("warnings %v do not mention %q", warnings, tc.MessageContains)
					}
				}
			default:
				t.Fatalf("unknown expectation %q", tc.Expect)
			}
		})
	}
}
