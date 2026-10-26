package config

import "fmt"

// Cooldown warning texts.
const (
	WarnShunWithoutCooldown   = "RAN_SHUN has no effect while RAN_ALERT_COOLDOWN is 0s; a shun window lasts for the alert cooldown."
	WarnRepeatWithoutCooldown = "RAN_REPEAT_COOLDOWN has no effect while RAN_ALERT_COOLDOWN is 0s, because the cooldown is disabled."
	WarnRepeatBelowCooldown   = "RAN_REPEAT_COOLDOWN is smaller than RAN_ALERT_COOLDOWN; the repeat cooldown is meant to be longer than the base cooldown."
)

// CooldownWarnings lists the settings that are accepted but cannot do anything
// useful: RAN_SHUN and RAN_REPEAT_COOLDOWN while the alert cooldown is off, and a
// repeat cooldown that is shorter than the base cooldown.
func (c *Config) CooldownWarnings() []string {
	var out []string
	if c.AlertCooldown <= 0 {
		if c.Shun {
			out = append(out, WarnShunWithoutCooldown)
		}
		if c.RepeatCooldown > 0 {
			out = append(out, WarnRepeatWithoutCooldown)
		}
		return out
	}
	if c.RepeatCooldown > 0 && c.RepeatCooldown < c.AlertCooldown {
		out = append(out, WarnRepeatBelowCooldown)
	}
	return out
}

// WarnShunWithoutCrowdSec is the warning for RAN_SHUN while RAN_CROWDSEC is off.
const WarnShunWithoutCrowdSec = "RAN_SHUN has no effect without RAN_CROWDSEC; shunning starts after an accepted alert"

// CrowdSecWarnings lists the settings that need the CrowdSec sink but are set
// while it is off: the shun window opens after an accepted alert, and only the
// sink accepts alerts.
func (c *Config) CrowdSecWarnings() []string {
	if c.Shun && !c.CrowdSec {
		return []string{WarnShunWithoutCrowdSec}
	}
	return nil
}

// Warnings lists every accepted-but-ineffective setting that Load can detect:
// PROXY entries for traps that are not enabled, a trusted list without PROXY
// protocol, the cooldown warnings and the CrowdSec warnings. `ran check-config`
// prints them and the documentation builder (through the WebAssembly check)
// shows the same list, so there is one source for both.
func (c *Config) Warnings() []string {
	var out []string
	if c.ProxyTrustedUnused() {
		out = append(out, "RAN_PROXY_TRUSTED is set but RAN_PROXY_PROTOCOL is off; the list is ignored")
	}
	for _, name := range c.ProxyNotEnabled {
		out = append(out, fmt.Sprintf("RAN_PROXY_PROTOCOL names %s, which is not in RAN_TRAPS; the entry has no effect", name))
	}
	out = append(out, c.CrowdSecWarnings()...)
	out = append(out, c.CooldownWarnings()...)
	return out
}

// Diagnosis is the outcome of checking an environment: the first error Load
// reports (empty when the configuration is valid) and, for a valid one, the
// warnings.
type Diagnosis struct {
	Error    string   `json:"error"`
	Warnings []string `json:"warnings"`
}

// Diagnose runs Load on getenv and reports the result without starting
// anything. It is what the documentation builder calls through WebAssembly.
func Diagnose(getenv func(string) string) Diagnosis {
	c, err := Load(getenv)
	if err != nil {
		return Diagnosis{Error: err.Error(), Warnings: []string{}}
	}
	w := c.Warnings()
	if w == nil {
		w = []string{}
	}
	return Diagnosis{Warnings: w}
}
