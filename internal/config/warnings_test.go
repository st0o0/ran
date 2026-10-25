package config_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/st0o0/ran/internal/config"
)

func TestCooldownWarnings(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		env  map[string]string
		want []string
	}{
		{"defaults", nil, nil},
		{"shun with default cooldown", map[string]string{"RAN_SHUN": "on"}, nil},
		{"shun without cooldown", map[string]string{"RAN_SHUN": "on", "RAN_ALERT_COOLDOWN": "0s"}, []string{config.WarnShunWithoutCooldown}},
		{"repeat without cooldown", map[string]string{"RAN_REPEAT_COOLDOWN": "12h", "RAN_ALERT_COOLDOWN": "0s"}, []string{config.WarnRepeatWithoutCooldown}},
		{"both without cooldown", map[string]string{"RAN_SHUN": "on", "RAN_REPEAT_COOLDOWN": "12h", "RAN_ALERT_COOLDOWN": "0"}, []string{config.WarnShunWithoutCooldown, config.WarnRepeatWithoutCooldown}},
		{"repeat below cooldown", map[string]string{"RAN_REPEAT_COOLDOWN": "30m"}, []string{config.WarnRepeatBelowCooldown}},
		{"repeat equals cooldown", map[string]string{"RAN_REPEAT_COOLDOWN": "1h"}, nil},
		{"repeat above cooldown", map[string]string{"RAN_REPEAT_COOLDOWN": "12h"}, nil},
		{"cooldown off, nothing set", map[string]string{"RAN_ALERT_COOLDOWN": "0s"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := config.Load(func(k string) string {
				if k == "RAN_TRAPS" {
					return "ssh"
				}
				return tc.env[k]
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := c.CooldownWarnings(); !slices.Equal(got, tc.want) {
				t.Errorf("warnings = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCrowdSecWarnings(t *testing.T) {
	t.Parallel()
	cs := map[string]string{"RAN_CROWDSEC": "on", "RAN_CROWDSEC_URL": "http://localhost:8080", "RAN_CROWDSEC_MACHINE_ID": "ran", "RAN_CROWDSEC_PASSWORD": "x"}
	cases := []struct {
		name string
		env  map[string]string
		want []string
	}{
		{"defaults", nil, nil},
		{"shun without crowdsec", map[string]string{"RAN_SHUN": "on"}, []string{config.WarnShunWithoutCrowdSec}},
		{"shun with crowdsec", map[string]string{"RAN_SHUN": "on"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			withCS := tc.name == "shun with crowdsec"
			c, err := config.Load(func(k string) string {
				if k == "RAN_TRAPS" {
					return "ssh"
				}
				if v, ok := tc.env[k]; ok {
					return v
				}
				if withCS {
					return cs[k]
				}
				return ""
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := c.CrowdSecWarnings(); !slices.Equal(got, tc.want) {
				t.Errorf("warnings = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCooldownUpperBound(t *testing.T) {
	t.Parallel()
	load := func(env map[string]string) (*config.Config, error) {
		env["RAN_TRAPS"] = "ssh"
		return config.Load(func(k string) string { return env[k] })
	}
	for _, name := range []string{"RAN_ALERT_COOLDOWN", "RAN_REPEAT_COOLDOWN"} {
		if c, err := load(map[string]string{name: "8760h"}); err != nil {
			t.Errorf("%s=8760h rejected: %v", name, err)
		} else if name == "RAN_ALERT_COOLDOWN" && c.AlertCooldown != config.MaxCooldown {
			t.Errorf("alert cooldown = %s", c.AlertCooldown)
		}
		for _, v := range []string{"8760h1s", "8761h", "2562047h"} {
			_, err := load(map[string]string{name: v})
			if err == nil || !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), "8760h") {
				t.Errorf("%s=%s: err = %v, want a cap error naming the variable", name, v, err)
			}
		}
	}
}
