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
