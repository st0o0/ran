package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCheckConfigCooldownWarnings(t *testing.T) {
	t.Parallel()
	env := map[string]string{"RAN_TRAPS": "ssh", "RAN_SHUN": "on", "RAN_REPEAT_COOLDOWN": "12h", "RAN_ALERT_COOLDOWN": "0s"}
	var out, errb bytes.Buffer
	code := checkConfig(func(k string) string { return env[k] }, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	for _, want := range []string{"RAN_SHUN has no effect while RAN_ALERT_COOLDOWN", "RAN_REPEAT_COOLDOWN has no effect while RAN_ALERT_COOLDOWN"} {
		if !strings.Contains(errb.String(), want) {
			t.Errorf("stderr %q lacks %q", errb.String(), want)
		}
	}
}
