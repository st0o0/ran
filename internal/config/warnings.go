package config

// Cooldown warning texts. The documentation builder (rules.ts) uses the same
// wording, and the shared builder cases keep the two in line.
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
