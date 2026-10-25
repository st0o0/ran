package config

import "sort"

// Setting describes one configuration variable. Settings is the register behind
// the documentation site's config builder: docgen serializes it to
// docs/data/settings.generated.json and settings_test.go keeps it in line with
// what Load reads.
type Setting struct {
	// Name is the environment variable. For a family it is the template
	// RAN_<PROTO>_SUFFIX.
	Name string `json:"name"`
	// Kind is one of bool, int, duration, string, enum, list, addr.
	Kind string `json:"kind"`
	// Default is the value Load uses when the variable is unset, written as an
	// operator would write it ("" when there is none or it is derived).
	Default string `json:"default"`
	// Group is the section of the builder (core, limits, logging, ...).
	Group string `json:"group"`
	// Summary is a one-line description.
	Summary string `json:"summary"`
	// Requires lists variables that must be set (or switched on) for this one
	// to have an effect.
	Requires []string `json:"requires,omitempty"`
	// Family is the variable suffix of a per-trap family (for example
	// "SESSION_TIMEOUT" for RAN_<PROTO>_SESSION_TIMEOUT); empty for a single
	// variable.
	Family string `json:"family,omitempty"`
	// Traps lists the traps a family applies to.
	Traps []string `json:"traps,omitempty"`
	// Enum lists the accepted values of an enum.
	Enum []string `json:"enum,omitempty"`
}

// Setting kinds.
const (
	KindBool     = "bool"
	KindInt      = "int"
	KindDuration = "duration"
	KindString   = "string"
	KindEnum     = "enum"
	KindList     = "list"
	KindAddr     = "addr"
)

func addrFamilyTraps() []string {
	var out []string
	for n := range DefaultPorts {
		out = append(out, n)
	}
	out = append(out, "catchall")
	sort.Strings(out)
	return out
}

func authFamilyTraps() []string { return ValidTrapNames() }

// Settings is the register of every variable Load reads, except the removed
// ones (RemovedEnvVars). Per-trap variables are single entries with Family.
var Settings = []Setting{
	// core
	{Name: "RAN_TRAPS", Kind: KindList, Group: "core", Summary: "Comma-separated list of traps to enable; at least one is required."},
	{Name: "RAN_METRICS_ADDR", Kind: KindAddr, Default: ":9550", Group: "core", Summary: "Listen address of the Prometheus metrics endpoint."},
	{Name: "RAN_SSH_HOST_KEY_PATH", Kind: KindString, Default: "/data/ssh_host_key", Group: "core", Summary: "File that persists the SSH host key."},
	{Name: "RAN_HTTPS_CERT_PATH", Kind: KindString, Default: "/data/https_cert.pem", Group: "core", Summary: "File that persists the self-signed HTTPS certificate."},
	{Name: "RAN_BANNER_SERVICES", Kind: KindString, Group: "core", Summary: "Services of the banner trap as port=name:banner pairs."},
	{Name: "RAN_HTTP_FIXTURES", Kind: KindString, Group: "http", Summary: "Path of a file with operator fixtures served by the http and https traps."},
	{Name: "RAN_<PROTO>_ADDR", Kind: KindAddr, Group: "core", Family: "ADDR", Traps: addrFamilyTraps(), Summary: "Listen addresses of one trap, comma separated; each trap has its own default port (see the trap table). Required for catchall."},

	// fingerprint
	{Name: "RAN_FINGERPRINT", Kind: KindEnum, Default: "seeded", Enum: []string{"seeded", "fixed"}, Group: "fingerprint", Summary: "Banner profile: seeded picks per-instance banners from a persisted seed, fixed uses the built-in ones."},
	{Name: "RAN_FINGERPRINT_SEED_PATH", Kind: KindString, Default: "/data/fingerprint_seed", Group: "fingerprint", Requires: []string{"RAN_FINGERPRINT"}, Summary: "File that persists the fingerprint seed."},

	// logging
	{Name: "RAN_LOG_LEVEL", Kind: KindEnum, Default: "info", Enum: []string{"debug", "info", "warn", "error"}, Group: "logging", Summary: "Log level."},
	{Name: "RAN_LOG_FORMAT", Kind: KindEnum, Default: "json", Enum: []string{"json", "text"}, Group: "logging", Summary: "Log output format."},
	{Name: "RAN_LOG_PASSWORDS", Kind: KindEnum, Default: "off", Enum: []string{"off", "mask", "on"}, Group: "logging", Summary: "Whether captured passwords are logged: off, masked or in clear text."},
	{Name: "RAN_PROBE_SUMMARY_WINDOW", Kind: KindDuration, Default: "60s", Group: "logging", Summary: "Aggregation window of probe log lines; 0s logs every probe session."},

	// limits
	{Name: "RAN_SESSION_TIMEOUT", Kind: KindDuration, Default: "30s", Group: "limits", Summary: "Default session deadline."},
	{Name: "RAN_MAX_SESSIONS", Kind: KindInt, Default: "500", Group: "limits", Summary: "Maximum concurrent sessions."},
	{Name: "RAN_MAX_PER_IP", Kind: KindInt, Default: "10", Group: "limits", Summary: "Maximum concurrent sessions per source address."},
	{Name: "RAN_MAX_AUTH_RETRIES", Kind: KindInt, Default: "3", Group: "limits", Summary: "Login attempts accepted per session before the connection is closed."},
	{Name: "RAN_AUTH_DELAY", Kind: KindDuration, Default: "0s", Group: "limits", Summary: "Delay before answering a login attempt."},
	{Name: "RAN_<PROTO>_MAX_AUTH_RETRIES", Kind: KindInt, Group: "limits", Family: "MAX_AUTH_RETRIES", Traps: authFamilyTraps(), Summary: "Per-trap override of RAN_MAX_AUTH_RETRIES; unset inherits the global value."},
	{Name: "RAN_<PROTO>_AUTH_DELAY", Kind: KindDuration, Group: "limits", Family: "AUTH_DELAY", Traps: authFamilyTraps(), Summary: "Per-trap override of RAN_AUTH_DELAY; unset inherits the global value."},
	{Name: "RAN_<PROTO>_SESSION_TIMEOUT", Kind: KindDuration, Group: "limits", Family: "SESSION_TIMEOUT", Traps: authFamilyTraps(), Summary: "Per-trap override of RAN_SESSION_TIMEOUT; unset inherits the global value."},

	// ssh
	{Name: "RAN_SSH_TARPIT", Kind: KindBool, Default: "off", Group: "ssh", Summary: "Slow down SSH sessions that fail authentication."},
	{Name: "RAN_SSH_TARPIT_DURATION", Kind: KindDuration, Default: "30s", Group: "ssh", Requires: []string{"RAN_SSH_TARPIT"}, Summary: "How long the SSH tarpit holds a session."},

	// proxy
	{Name: "RAN_PROXY_PROTOCOL", Kind: KindString, Default: "off", Group: "proxy", Summary: "PROXY protocol: on (all TCP traps), off, or a comma-separated list of TCP traps. UDP traps cannot use it."},
	{Name: "RAN_PROXY_TRUSTED", Kind: KindList, Group: "proxy", Requires: []string{"RAN_PROXY_PROTOCOL"}, Summary: "IP addresses or CIDR ranges of the proxies allowed to send PROXY headers, or any. Required when PROXY protocol is used."},

	// ignore
	{Name: "RAN_IGNORE_IPS", Kind: KindList, Group: "ignore", Summary: "IP addresses or CIDR ranges that are served and logged but never alert."},

	// udp
	{Name: "RAN_UDP_RATE_PER_SOURCE", Kind: KindInt, Default: "20", Group: "udp", Summary: "Packets per second accepted per UDP source."},
	{Name: "RAN_UDP_RATE_BURST", Kind: KindInt, Default: "40", Group: "udp", Summary: "UDP burst size per source; must not be smaller than the per-source rate."},
	{Name: "RAN_UDP_RATE_GLOBAL", Kind: KindInt, Default: "2000", Group: "udp", Summary: "Packets per second accepted across all UDP sources."},

	// crowdsec
	{Name: "RAN_CROWDSEC", Kind: KindBool, Default: "off", Group: "crowdsec", Summary: "Report alerts to a CrowdSec local API."},
	{Name: "RAN_CROWDSEC_URL", Kind: KindString, Group: "crowdsec", Requires: []string{"RAN_CROWDSEC"}, Summary: "URL of the CrowdSec local API."},
	{Name: "RAN_CROWDSEC_MACHINE_ID", Kind: KindString, Group: "crowdsec", Requires: []string{"RAN_CROWDSEC"}, Summary: "Machine ID registered with cscli machines add."},
	{Name: "RAN_CROWDSEC_PASSWORD", Kind: KindString, Group: "crowdsec", Requires: []string{"RAN_CROWDSEC"}, Summary: "Machine password. Secret: never put a real value into shared files."},
	{Name: "RAN_CROWDSEC_BATCH_INTERVAL", Kind: KindDuration, Default: "10s", Group: "crowdsec", Requires: []string{"RAN_CROWDSEC"}, Summary: "How often queued alerts are sent."},
	{Name: "RAN_CROWDSEC_BATCH_SIZE", Kind: KindInt, Default: "50", Group: "crowdsec", Requires: []string{"RAN_CROWDSEC"}, Summary: "Maximum alerts per batch."},
	{Name: "RAN_CROWDSEC_MAX_TRACKED", Kind: KindInt, Default: "20000", Group: "crowdsec", Requires: []string{"RAN_CROWDSEC"}, Summary: "Maximum source addresses tracked for scan detection."},
	{Name: "RAN_BAN_ON", Kind: KindList, Default: "attack,scan", Group: "crowdsec", Requires: []string{"RAN_CROWDSEC"}, Summary: "Session classes that produce an alert: any of probe, attack, scan."},
	{Name: "RAN_ALERT_COOLDOWN", Kind: KindDuration, Default: "1h", Group: "crowdsec", Requires: []string{"RAN_CROWDSEC"}, Summary: "At most one alert per source and class in this window; 0s disables the limit."},
}
