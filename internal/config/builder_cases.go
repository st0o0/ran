package config

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
		{ID: "error-no-trap", Env: map[string]string{}, Expect: "error", MessageContains: "at least one trap"},
		{ID: "error-catchall-without-addr", Env: map[string]string{"RAN_TRAPS": "catchall"}, Expect: "error", MessageContains: "RAN_CATCHALL_ADDR"},
		{ID: "error-crowdsec-without-url", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_CROWDSEC": "on"}, Expect: "error", MessageContains: "RAN_CROWDSEC_URL"},
		{ID: "ok-repeat-cooldown-above-alert", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_REPEAT_COOLDOWN": "12h"}, Expect: "ok"},
		{ID: "ok-shun-with-cooldown", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_SHUN": "on"}, Expect: "ok"},
		{ID: "warning-shun-without-alert-cooldown", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_SHUN": "on", "RAN_ALERT_COOLDOWN": "0s"}, Expect: "warning", MessageContains: "RAN_SHUN has no effect"},
		{ID: "warning-repeat-cooldown-without-alert-cooldown", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_REPEAT_COOLDOWN": "12h", "RAN_ALERT_COOLDOWN": "0s"}, Expect: "warning", MessageContains: "RAN_REPEAT_COOLDOWN has no effect"},
		{ID: "warning-repeat-cooldown-below-alert-cooldown", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_REPEAT_COOLDOWN": "30m"}, Expect: "warning", MessageContains: "smaller than RAN_ALERT_COOLDOWN"},
		{ID: "error-repeat-after-zero", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_REPEAT_AFTER": "0"}, Expect: "error", MessageContains: "RAN_REPEAT_AFTER"},
		{ID: "error-max-sessions-zero", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_MAX_SESSIONS": "0"}, Expect: "error", MessageContains: "RAN_MAX_SESSIONS"},
		{ID: "error-repeat-cooldown-zero", Env: map[string]string{"RAN_TRAPS": "ssh", "RAN_REPEAT_COOLDOWN": "0s"}, Expect: "error", MessageContains: "RAN_REPEAT_COOLDOWN"},
	}
}
