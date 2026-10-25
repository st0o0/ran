package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/st0o0/ran/internal/fingerprint"
)

func TestFingerprintDefaults(t *testing.T) {
	c, err := Load(envFunc(map[string]string{"RAN_TRAPS": "ssh"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.FingerprintMode != "seeded" {
		t.Errorf("FingerprintMode = %q, want seeded", c.FingerprintMode)
	}
	if c.FingerprintSeedPath != "/data/fingerprint_seed" {
		t.Errorf("FingerprintSeedPath = %q", c.FingerprintSeedPath)
	}
}

func TestFingerprintModeValues(t *testing.T) {
	for in, want := range map[string]string{"seeded": "seeded", "fixed": "fixed", " FIXED ": "fixed", "Seeded": "seeded"} {
		c, err := Load(envFunc(map[string]string{"RAN_TRAPS": "ssh", "RAN_FINGERPRINT": in}))
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if c.FingerprintMode != want {
			t.Errorf("%q: mode = %q, want %q", in, c.FingerprintMode, want)
		}
	}
}

func TestFingerprintModeInvalid(t *testing.T) {
	for _, in := range []string{"random", "on", "1", "seed"} {
		_, err := Load(envFunc(map[string]string{"RAN_TRAPS": "ssh", "RAN_FINGERPRINT": in}))
		if err == nil || !strings.Contains(err.Error(), "RAN_FINGERPRINT") {
			t.Errorf("%q: err = %v, want an error naming RAN_FINGERPRINT", in, err)
		}
	}
}

func TestFingerprintFixedUsesOriginalValuesWithoutFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "seed")
	c, err := Load(envFunc(map[string]string{"RAN_TRAPS": "ssh", "RAN_FINGERPRINT": "fixed", "RAN_FINGERPRINT_SEED_PATH": path}))
	if err != nil {
		t.Fatal(err)
	}
	p := c.Fingerprint(nil)
	if p.SSH != "SSH-2.0-OpenSSH_9.6" || p.MySQL != "8.0.36" || p.HTTP.Server != "Apache/2.4.62" {
		t.Errorf("fixed profile = %+v", p)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("fixed mode wrote the seed file (err = %v)", err)
	}
}

func TestFingerprintSeededIsResolvedOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seed")
	env := map[string]string{"RAN_TRAPS": "ssh", "RAN_FINGERPRINT_SEED_PATH": path}
	c, err := Load(envFunc(env))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("Load must not write the seed (check-config has no side effects)")
	}
	a, b := c.Fingerprint(nil), c.Fingerprint(nil)
	if a != b {
		t.Error("Fingerprint returned different profiles")
	}
	if a.Mode != fingerprint.ModeSeeded {
		t.Errorf("mode = %q", a.Mode)
	}
	// A second process (restart) with the same file gets the same banners.
	c2, _ := Load(envFunc(env))
	if *c2.Fingerprint(nil) != *a {
		t.Error("restart changed the profile")
	}
}

func TestFingerprintLiteralConfigIsFixed(t *testing.T) {
	c := &Config{}
	if p := c.Fingerprint(nil); *p != *fingerprint.Fixed() {
		t.Errorf("literal config profile = %+v", p)
	}
	custom := fingerprint.FromSeed(make([]byte, 32))
	c.SetFingerprint(custom)
	if c.Fingerprint(nil) != custom {
		t.Error("SetFingerprint ignored")
	}
}
