package main

import (
	"os"
	"strings"
	"testing"
)

// TestGeneratedTrapTableIsCurrent fails when docs/traps.generated.md differs
// from the generator output. Regenerate with `go run ./internal/tools/docgen`.
func TestGeneratedTrapTableIsCurrent(t *testing.T) {
	raw, err := os.ReadFile("../../../" + defaultOut)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.ReplaceAll(string(raw), "\r\n", "\n")
	if got != render() {
		t.Errorf("%s is out of date; run `go run ./internal/tools/docgen` from the repository root", defaultOut)
	}
}

func TestRenderIsSortedAndComplete(t *testing.T) {
	out := render()
	if strings.Contains(out, "\r") {
		t.Error("output must use LF line endings")
	}
	for _, want := range []string{"| `banner` | none (required) | TCP | `RAN_BANNER_SERVICES` |", "| `dns` | `:53` | UDP | `RAN_DNS_ADDR` |", "| `telnet` | `:23`, `:2323` | TCP |"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing row %q", want)
		}
	}
	if strings.Index(out, "`adb`") > strings.Index(out, "`catchall`") {
		t.Error("rows not sorted")
	}
}

func checkCurrent(t *testing.T, path, want string) {
	t.Helper()
	raw, err := os.ReadFile("../../../" + path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.ReplaceAll(string(raw), "\r\n", "\n"); got != want {
		t.Errorf("%s is out of date; run `go run ./internal/tools/docgen` from the repository root", path)
	}
}

// TestGeneratedSettingsAreCurrent fails when the settings register or the
// builder cases changed without regenerating the JSON files.
func TestGeneratedSettingsAreCurrent(t *testing.T) {
	checkCurrent(t, settingsOut, renderSettings())
	checkCurrent(t, casesOut, renderCases())
}

func TestRenderSettingsIsStable(t *testing.T) {
	out := renderSettings()
	if out != renderSettings() || strings.Contains(out, "\r") || !strings.HasSuffix(out, "}\n") {
		t.Error("settings JSON must be deterministic, LF only and end with a newline")
	}
	if strings.Index(out, `"RAN_ALERT_COOLDOWN"`) > strings.Index(out, `"RAN_CROWDSEC"`) {
		t.Error("settings not sorted by group then name")
	}
	if !strings.Contains(out, `"addressless": true`) {
		t.Error("addressless traps missing")
	}
}

// TestGeneratedProfileIsCurrent fails when the embedded CrowdSec profile changed
// without regenerating docs/crowdsec-profile.generated.md.
func TestGeneratedProfileIsCurrent(t *testing.T) {
	checkCurrent(t, profileOut, renderProfile())
}

func TestRenderProfileShape(t *testing.T) {
	out := renderProfile()
	if strings.Contains(out, "\r") || !strings.Contains(out, "```yaml\n") {
		t.Error("profile fragment must be LF only and start a yaml fence")
	}
	if !strings.HasSuffix(out, "```\n") {
		t.Error("fence not closed")
	}
}
