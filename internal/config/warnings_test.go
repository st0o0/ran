package config_test

import (
	"slices"
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
