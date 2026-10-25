package crowdsecprofile

import (
	"strings"
	"testing"
)

// docs splits the multi-document YAML into per-profile line lists. A real YAML
// parser is not a dependency of the module, and the structure is flat, so a
// line based check is enough; the integration test (build tag crowdsec) proves
// the semantics against a real CrowdSec.
func docs(t *testing.T) [][]string {
	t.Helper()
	var out [][]string
	var cur []string
	for _, l := range strings.Split(YAML(), "\n") {
		if strings.TrimRight(l, " ") == "---" {
			out = append(out, cur)
			cur = nil
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(l), "#") || strings.TrimSpace(l) == "" {
			continue
		}
		cur = append(cur, l)
	}
	return append(out, cur)
}

func has(lines []string, want string) bool {
	for _, l := range lines {
		if l == want {
			return true
		}
	}
	return false
}

func TestProfileStructure(t *testing.T) {
	d := docs(t)
	if len(d) != 3 {
		t.Fatalf("want 3 profiles, got %d", len(d))
	}
	const formula = `duration_expr: "Sprintf('%.0fh', min(168.0, 3 ^ GetDecisionsCount(Alert.GetValue())))"`
	wants := []struct {
		name, class string
		ban         bool
	}{
		{"ran_scan", "scan", true},
		{"ran_attack", "attack", true},
		{"ran_noban", "", false},
	}
	for i, w := range wants {
		p := d[i]
		if !has(p, "name: "+w.name) {
			t.Errorf("profile %d: want name %s", i, w.name)
		}
		if !has(p, "on_success: break") {
			t.Errorf("%s: missing on_success: break", w.name)
		}
		if has(p, "filter:") || !has(p, "filters:") {
			t.Errorf("%s: must use the list key filters:", w.name)
		}
		filter := `  - Alert.GetScenario() startsWith "custom/ran-"`
		if w.class != "" {
			filter += ` && Alert.Events[0].GetMeta("class") == "` + w.class + `"`
		}
		if !has(p, filter) {
			t.Errorf("%s: filter %q not found", w.name, filter)
		}
		if w.ban != has(p, "decisions:") || w.ban != has(p, formula) {
			t.Errorf("%s: decisions/duration_expr presence must be %v", w.name, w.ban)
		}
	}
}

func TestProfilePitfalls(t *testing.T) {
	y := YAML()
	if strings.Contains(y, "Alert.GetMeta(") {
		t.Error("Alert.GetMeta reads alert level meta only; use Alert.Events[0].GetMeta")
	}
	if strings.Contains(y, "Min(") || strings.Contains(y, "%dh") || strings.Contains(y, "min(168,") {
		t.Error("duration_expr pitfall: lowercase min, a float literal and the float format verb are required")
	}
	if strings.Contains(y, "Remediation") {
		t.Error("the shipped profile must not carry a Remediation fallback")
	}
	if strings.Contains(y, "\r") || !strings.HasSuffix(y, "\n") {
		t.Error("profile must use LF and end with a newline")
	}
}

func TestTestedVersion(t *testing.T) {
	if got := TestedVersion(); !strings.HasPrefix(got, "v") || strings.ContainsAny(got, ":@") {
		t.Errorf("TestedVersion() = %q, want a tag like v1.8.1", got)
	}
	if !strings.Contains(TestedImage, "@sha256:") {
		t.Error("TestedImage must be pinned by digest")
	}
}
