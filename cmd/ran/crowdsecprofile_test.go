package main

import (
	"bytes"
	"testing"

	"github.com/st0o0/ran/internal/crowdsecprofile"
)

func TestPrintCrowdSecProfile(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	if code := printCrowdSecProfile(&out); code != 0 {
		t.Fatalf("exit %d, want 0", code)
	}
	if out.String() != crowdsecprofile.YAML() || out.Len() == 0 {
		t.Error("output must be the embedded profile")
	}
}

func TestCrowdSecProfileSubcommandNeedsNoConfig(t *testing.T) {
	// An invalid configuration must not matter: the subcommand returns before
	// config.Load.
	t.Setenv("RAN_TRAPS", "no-such-trap")
	if code := realMain([]string{"crowdsec-profile"}); code != 0 {
		t.Fatalf("exit %d, want 0", code)
	}
}
