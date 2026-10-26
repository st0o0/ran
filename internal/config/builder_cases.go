package config

import (
	"fmt"
	"strings"
)

// BuilderCase is one shared test vector for the configuration rules: an
// environment and the outcome config.Load must produce. docgen writes the cases
// to docs/data/builder-cases.json, where the documentation builder replays them
// too, so the two implementations cannot disagree silently.
//
// Expect is "ok" (Load succeeds, no warning), "error" (Load fails with an error
// containing MessageContains) or "warning" (Load succeeds but reports a startup
// warning; MessageContains names the variable or trap the warning is about).
type BuilderCase struct {
	ID              string            `json:"id"`
	Env             map[string]string `json:"env"`
	Expect          string            `json:"expect"`
	MessageContains string            `json:"message_contains,omitempty"`
}

// BuilderCases returns the shared rule vectors in a stable order.
func BuilderCases() []BuilderCase {
	return []BuilderCase{
		{ID: "ok-minimal", Env: map[string]string{"RAN_TRAPS": "ssh"}, Expect: "ok"},
		{ID: "ok-proxy-list-trusted", Env: map[string]string{"RAN_TRAPS": "ssh,http", "RAN_PROXY_PROTOCOL": "http", "RAN_PROXY_TRUSTED": "127.0.0.1,::1"}, Expect: "ok"},
		{ID: "ok-proxy-on-trusted-any", Env: map[string]string{"RAN_TRAPS": "ssh,http", "RAN_PROXY_PROTOCOL": "on", "RAN_PROXY_TRUSTED": "any"}, Expect: "ok"},
		{ID: "ok-udp-trap-without-proxy", Env: map[string]string{"RAN_TRAPS": "dns,http", "RAN_PROXY_PROTOCOL": "http", "RAN_PROXY_TRUSTED": "127.0.0.1"}, Expect: "ok"},
		{ID: "ok-udp-burst-equals-rate", Env: map[string]string{"RAN_TRAPS": "dns", "RAN_UDP_RATE_PER_SOURCE": "20", "RAN_UDP_RATE_BURST": "20"}, Expect: "ok"},
		{ID: "ok-catchall-with-addr", Env: map[string]string{"RAN_TRAPS": "catchall", "RAN_CATCHALL_ADDR": ":4444"}, Expect: "ok"},
		{ID: "error-proxy-on-without-trusted", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_PROXY_PROTOCOL": "on"}, Expect: "error", MessageContains: "RAN_PROXY_TRUSTED"},
		{ID: "error-proxy-list-without-trusted", Env: map[string]string{"RAN_TRAPS": "http", "RAN_PROXY_PROTOCOL": "http"}, Expect: "error", MessageContains: "RAN_PROXY_TRUSTED"},
		{ID: "error-udp-trap-in-proxy-list", Env: map[string]string{"RAN_TRAPS": "ssh,dns", "RAN_PROXY_PROTOCOL": "dns", "RAN_PROXY_TRUSTED": "127.0.0.1"}, Expect: "error", MessageContains: "UDP trap"},
		{ID: "error-unknown-trap-in-proxy-list", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_PROXY_PROTOCOL": "bogus", "RAN_PROXY_TRUSTED": "127.0.0.1"}, Expect: "error", MessageContains: "unknown trap"},
		{ID: "warning-proxy-trap-not-enabled", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_PROXY_PROTOCOL": "http", "RAN_PROXY_TRUSTED": "127.0.0.1"}, Expect: "warning", MessageContains: "http"},
		{ID: "warning-trusted-without-proxy", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_PROXY_TRUSTED": "127.0.0.1"}, Expect: "warning", MessageContains: "RAN_PROXY_TRUSTED"},
		{ID: "error-udp-burst-below-rate", Env: map[string]string{"RAN_TRAPS": "dns", "RAN_UDP_RATE_PER_SOURCE": "20", "RAN_UDP_RATE_BURST": "10"}, Expect: "error", MessageContains: "RAN_UDP_RATE_BURST"},
		{ID: "error-unknown-trap", Env: map[string]string{"RAN_TRAPS": "ssh,bogus"}, Expect: "error", MessageContains: "unknown trap"},
		{ID: "error-port-conflict", Env: map[string]string{"RAN_TRAPS": "ssh,http", "RAN_HTTP_ADDR": ":2222"}, Expect: "error", MessageContains: "both listen"},
		{ID: "error-port-conflict-banner", Env: map[string]string{"RAN_TRAPS": "ssh,banner", "RAN_BANNER_SERVICES": "2222=custom:hello"}, Expect: "error", MessageContains: "both listen"},
		{ID: "ok-same-port-tcp-and-udp", Env: map[string]string{"RAN_TRAPS": "dns,catchall", "RAN_CATCHALL_ADDR": ":53"}, Expect: "ok"},
		{ID: "error-no-trap", Env: map[string]string{}, Expect: "error", MessageContains: "at least one trap"},
		{ID: "error-catchall-without-addr", Env: map[string]string{"RAN_TRAPS": "catchall"}, Expect: "error", MessageContains: "RAN_CATCHALL_ADDR"},
		{ID: "error-crowdsec-without-url", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_CROWDSEC": "on"}, Expect: "error", MessageContains: "RAN_CROWDSEC_URL"},
		{ID: "ok-repeat-cooldown-above-alert", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_REPEAT_COOLDOWN": "12h"}, Expect: "ok"},
		{ID: "ok-shun-with-cooldown", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_CROWDSEC": "on", "RAN_CROWDSEC_URL": "http://localhost:8080", "RAN_CROWDSEC_MACHINE_ID": "ran", "RAN_CROWDSEC_PASSWORD": "x", "RAN_SHUN": "on"}, Expect: "ok"},
		{ID: "warning-shun-without-crowdsec", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_SHUN": "on"}, Expect: "warning", MessageContains: "has no effect without RAN_CROWDSEC"},
		{ID: "ok-repeat-cooldown-at-max", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_REPEAT_COOLDOWN": "8760h"}, Expect: "ok"},
		{ID: "ok-alert-cooldown-at-max", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_ALERT_COOLDOWN": "8760h"}, Expect: "ok"},
		{ID: "error-repeat-cooldown-too-long", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_REPEAT_COOLDOWN": "8761h"}, Expect: "error", MessageContains: "RAN_REPEAT_COOLDOWN"},
		{ID: "error-alert-cooldown-too-long", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_ALERT_COOLDOWN": "2562047h"}, Expect: "error", MessageContains: "RAN_ALERT_COOLDOWN"},
		{ID: "warning-shun-without-alert-cooldown", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_SHUN": "on", "RAN_ALERT_COOLDOWN": "0s"}, Expect: "warning", MessageContains: "RAN_SHUN has no effect"},
		{ID: "warning-repeat-cooldown-without-alert-cooldown", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_REPEAT_COOLDOWN": "12h", "RAN_ALERT_COOLDOWN": "0s"}, Expect: "warning", MessageContains: "RAN_REPEAT_COOLDOWN has no effect"},
		{ID: "warning-repeat-cooldown-below-alert-cooldown", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_REPEAT_COOLDOWN": "30m"}, Expect: "warning", MessageContains: "smaller than RAN_ALERT_COOLDOWN"},
		{ID: "error-repeat-after-zero", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_REPEAT_AFTER": "0"}, Expect: "error", MessageContains: "RAN_REPEAT_AFTER"},
		{ID: "error-max-sessions-zero", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_MAX_SESSIONS": "0"}, Expect: "error", MessageContains: "RAN_MAX_SESSIONS"},
		{ID: "error-repeat-cooldown-zero", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_REPEAT_COOLDOWN": "0s"}, Expect: "error", MessageContains: "RAN_REPEAT_COOLDOWN"},
		{ID: "ok-bool-spellings", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_CROWDSEC": "true", "RAN_CROWDSEC_URL": "http://localhost:8080", "RAN_CROWDSEC_MACHINE_ID": "ran", "RAN_CROWDSEC_PASSWORD": "x", "RAN_SHUN": "yes"}, Expect: "ok"},
		{ID: "error-bool-invalid", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_SSH_TARPIT": "maybe"}, Expect: "error", MessageContains: "RAN_SSH_TARPIT"},
		{ID: "ok-proxy-protocol-true", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_PROXY_PROTOCOL": "true", "RAN_PROXY_TRUSTED": "127.0.0.1"}, Expect: "ok"},
		{ID: "error-proxy-trusted-any-uppercase", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_PROXY_PROTOCOL": "on", "RAN_PROXY_TRUSTED": "ANY"}, Expect: "error", MessageContains: "RAN_PROXY_TRUSTED"},
		{ID: "error-proxy-trusted-any-mixed", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_PROXY_PROTOCOL": "on", "RAN_PROXY_TRUSTED": "any,127.0.0.1"}, Expect: "error", MessageContains: "RAN_PROXY_TRUSTED"},
		{ID: "error-proxy-trusted-bad-cidr", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_PROXY_PROTOCOL": "on", "RAN_PROXY_TRUSTED": "10.0.0.0/33"}, Expect: "error", MessageContains: "RAN_PROXY_TRUSTED"},
		{ID: "error-ignore-ips-invalid", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_IGNORE_IPS": "not-an-ip"}, Expect: "error", MessageContains: "RAN_IGNORE_IPS"},
		{ID: "error-ignore-ips-zone", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_IGNORE_IPS": "fe80::1%eth0"}, Expect: "error", MessageContains: "RAN_IGNORE_IPS"},
		{ID: "error-ignore-ips-leading-zero", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_IGNORE_IPS": "01.2.3.4"}, Expect: "error", MessageContains: "RAN_IGNORE_IPS"},
		{ID: "ok-ignore-ips-mapped", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_IGNORE_IPS": "::ffff:8.8.8.8,8.8.8.8/32"}, Expect: "ok"},
		{ID: "error-ignore-ips-limit", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_IGNORE_IPS": manyIPs(1025)}, Expect: "error", MessageContains: "1024"},
		{ID: "error-ban-on-class", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_BAN_ON": "attack,flood"}, Expect: "error", MessageContains: "flood"},
		{ID: "error-ban-on-empty-list", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_BAN_ON": ","}, Expect: "error", MessageContains: "RAN_BAN_ON"},
		{ID: "error-int-int64-overflow", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_MAX_SESSIONS": "9223372036854775808"}, Expect: "error", MessageContains: "RAN_MAX_SESSIONS"},
		{ID: "error-udp-burst-above-2-pow-53", Env: map[string]string{"RAN_TRAPS": "dns", "RAN_UDP_RATE_PER_SOURCE": "9007199254740993", "RAN_UDP_RATE_BURST": "9007199254740992"}, Expect: "error", MessageContains: "RAN_UDP_RATE_BURST"},
	}
}

// manyIPs returns n distinct comma separated public IPv4 addresses.
func manyIPs(n int) string {
	parts := make([]string, 0, n)
	for i := 0; i < n; i++ {
		parts = append(parts, fmt.Sprintf("8.%d.%d.1", i/256, i%256))
	}
	return strings.Join(parts, ",")
}
