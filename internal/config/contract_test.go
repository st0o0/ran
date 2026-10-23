package config_test

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
)

// knownEnvVars records every variable Load reads when all traps are enabled.
func knownEnvVars(t *testing.T) []string {
	t.Helper()
	seen := map[string]bool{}
	allTraps := strings.Join(config.ValidTrapNames(), ",")
	_, err := config.Load(func(name string) string {
		seen[name] = true
		if name == "RAN_TRAPS" {
			return allTraps
		}
		return ""
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var envRef = regexp.MustCompile(`RAN_[A-Z][A-Z0-9_]*[A-Z0-9]`)

func TestREADMEMatchesConfig(t *testing.T) {
	raw, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(raw)

	known := map[string]bool{}
	for _, v := range knownEnvVars(t) {
		known[v] = true
	}
	removed := map[string]bool{}
	for _, v := range config.RemovedEnvVars {
		removed[v] = true
	}

	// Per-trap variables are documented once as RAN_<PROTO>_SUFFIX.
	perProto := map[string]bool{}
	for _, m := range regexp.MustCompile(`RAN_<PROTO>_([A-Z0-9_]+[A-Z0-9])`).FindAllStringSubmatch(readme, -1) {
		perProto[m[1]] = true
	}
	trapPrefix := func(name string) (suffix string, ok bool) {
		for trap := range config.ValidTraps {
			p := "RAN_" + strings.ToUpper(trap) + "_"
			if strings.HasPrefix(name, p) {
				return strings.TrimPrefix(name, p), true
			}
		}
		return "", false
	}

	mentioned := map[string]bool{}
	for _, ref := range envRef.FindAllString(readme, -1) {
		mentioned[ref] = true
	}

	for ref := range mentioned {
		if known[ref] || removed[ref] {
			continue
		}
		if suffix, ok := trapPrefix(ref); ok && known[ref] || ok && perProto[suffix] {
			continue
		}
		t.Errorf("README mentions %s, which is neither a config variable nor a removed one", ref)
	}

	for name := range known {
		if mentioned[name] {
			continue
		}
		if suffix, ok := trapPrefix(name); ok && perProto[suffix] {
			continue
		}
		t.Errorf("config variable %s is not documented in README", name)
	}
}

func TestMaxTrackedDefaultIsConsistent(t *testing.T) {
	cfg, err := config.Load(func(name string) string {
		if name == "RAN_TRAPS" {
			return "ssh"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CrowdSecMaxTracked != 20000 || alert.DefaultMaxTracked != 20000 {
		t.Errorf("max tracked defaults: config=%d alert=%d, want 20000", cfg.CrowdSecMaxTracked, alert.DefaultMaxTracked)
	}
	raw, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "`RAN_CROWDSEC_MAX_TRACKED` | `20000`") {
		t.Error("README must document the RAN_CROWDSEC_MAX_TRACKED default as 20000")
	}
}

func TestValidateAddrList(t *testing.T) {
	good := []string{":2222", "0.0.0.0:22,[::]:22", " :25 , :587", "localhost:80"}
	bad := []string{"2222", ":0", ":70000", "host:abc", ":22,,x", ",", "[::1:22"}
	for _, a := range good {
		if err := config.ValidateAddrList("RAN_X_ADDR", a); err != nil {
			t.Errorf("%q rejected: %v", a, err)
		}
	}
	for _, a := range bad {
		if err := config.ValidateAddrList("RAN_X_ADDR", a); err == nil {
			t.Errorf("%q accepted, want error", a)
		}
	}
}

func TestInvalidAddrAndSortedTrapNames(t *testing.T) {
	_, err := config.Load(func(name string) string {
		switch name {
		case "RAN_TRAPS":
			return "ssh"
		case "RAN_SSH_ADDR":
			return "nonsense"
		}
		return ""
	})
	if err == nil || !strings.Contains(err.Error(), "RAN_SSH_ADDR") || !strings.Contains(err.Error(), "for example") {
		t.Errorf("want addr error with remedy, got %v", err)
	}

	_, err = config.Load(func(name string) string {
		if name == "RAN_TRAPS" {
			return "bogus"
		}
		return ""
	})
	if err == nil {
		t.Fatal("want error for unknown trap")
	}
	names := config.ValidTrapNames()
	if !sort.StringsAreSorted(names) || !strings.Contains(err.Error(), strings.Join(names, ", ")) {
		t.Errorf("trap names not sorted in error: %v", err)
	}
}
