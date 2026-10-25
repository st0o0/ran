//go:build crowdsec

package alert

// Integration test: the production CrowdSecAlerter against a real CrowdSec LAPI
// that runs the shipped profile (internal/crowdsecprofile) followed by a generic
// Remediation == true profile, as an operator would have. It needs Docker and
// is skipped unless RAN_CROWDSEC_IT is set:
//
//	RAN_CROWDSEC_IT=1 go test -tags crowdsec ./internal/alert/ -run CrowdSecIntegration -v
//
// The container is driven through the docker CLI (no extra Go dependency). The
// alert IPs are public addresses because the sink rejects documentation ranges.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/st0o0/ran/internal/crowdsecprofile"
)

const (
	itMachineID   = "ran-it"
	itPassword    = "ran-it-password-0123456789"
	itBouncerName = "ran"
	itBouncerKey  = "ran-it-bouncer-key-0123456789"
	itTolerance   = 2 * time.Minute
)

type itDecision struct {
	Duration string `json:"duration"`
	Origin   string `json:"origin"`
	Scope    string `json:"scope"`
	Type     string `json:"type"`
	Value    string `json:"value"`
}

type itLAPI struct {
	t         *testing.T
	container string
	url       string
}

func itDocker(t *testing.T, args ...string) string {
	t.Helper()
	var out, errb bytes.Buffer
	cmd := exec.Command("docker", args...)
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("docker %s: %v\n%s%s", strings.Join(args, " "), err, out.String(), errb.String())
	}
	return strings.TrimSpace(out.String())
}

// startLAPI runs the pinned image as LAPI only with the shipped profile and waits
// until the LAPI answers /health.
func startLAPI(t *testing.T) *itLAPI {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("RAN_CROWDSEC_IT is set but docker is not available: %v", err)
	}

	dir := t.TempDir()
	profile := filepath.Join(dir, "profiles.yaml")
	if err := os.WriteFile(profile, []byte(crowdsecprofile.YAML()+itGenericProfile), 0o644); err != nil {
		t.Fatal(err)
	}

	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	name := "ran-crowdsec-it-" + hex.EncodeToString(suffix)

	id := itDocker(t, "run", "-d", "--name", name,
		"-p", "127.0.0.1::8080",
		// LAPI only, no Central API traffic, no volume for the sqlite database.
		"-e", "DISABLE_AGENT=true",
		"-e", "DISABLE_ONLINE_API=true",
		"-e", "CROWDSEC_BYPASS_DB_VOLUME_CHECK=true",
		// Machine and bouncer registered by the image entrypoint.
		"-e", "AGENT_USERNAME="+itMachineID,
		"-e", "AGENT_PASSWORD="+itPassword,
		"-e", "BOUNCER_KEY_"+itBouncerName+"="+itBouncerKey,
		"-v", profile+":/etc/crowdsec/profiles.yaml:ro",
		crowdsecprofile.TestedImage)
	l := &itLAPI{t: t, container: name}
	t.Cleanup(func() {
		if t.Failed() {
			logs, _ := exec.Command("docker", "logs", "--tail", "60", name).CombinedOutput()
			t.Logf("crowdsec container logs (tail):\n%s", logs)
		}
		_ = exec.Command("docker", "rm", "-f", name).Run()
	})
	_ = id

	hostPort := itDocker(t, "port", name, "8080/tcp")
	// "127.0.0.1:49153" (an IPv6 line may follow on some hosts).
	hostPort, _, _ = strings.Cut(hostPort, "\n")
	l.url = "http://" + strings.TrimSpace(hostPort)

	// Retry the readiness probe, not the assertions.
	deadline := time.Now().Add(120 * time.Second)
	for {
		resp, err := http.Get(l.url + "/health")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return l
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("LAPI at %s not ready after 120s (last error: %v)", l.url, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func (l *itLAPI) cscli(args ...string) string {
	l.t.Helper()
	return itDocker(l.t, append([]string{"exec", l.container, "cscli"}, args...)...)
}

// decisions returns the active decisions of ip as the bouncer sees them.
func (l *itLAPI) decisions(ip string) []itDecision {
	l.t.Helper()
	req, err := http.NewRequest(http.MethodGet, l.url+"/v1/decisions?ip="+ip, nil)
	if err != nil {
		l.t.Fatal(err)
	}
	req.Header.Set("X-Api-Key", itBouncerKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		l.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		l.t.Fatalf("GET /v1/decisions: %d %s", resp.StatusCode, body)
	}
	var out []itDecision // the LAPI answers "null" without decisions
	if err := json.Unmarshal(body, &out); err != nil {
		l.t.Fatalf("decode %q: %v", body, err)
	}
	return out
}

// maxRemaining returns the longest remaining duration among the ban decisions.
func itMaxRemaining(t *testing.T, ds []itDecision) time.Duration {
	t.Helper()
	var best time.Duration
	for _, d := range ds {
		if d.Type != "ban" {
			continue
		}
		dur, err := time.ParseDuration(d.Duration)
		if err != nil {
			t.Fatalf("decision duration %q: %v", d.Duration, err)
		}
		best = max(best, dur)
	}
	return best
}

// alertCount returns the number of stored alerts for ip.
func (l *itLAPI) alertCount(ip string) int {
	l.t.Helper()
	// -a: alerts without an active decision (probe, allowlist) are hidden by default;
	// --ip does not match them in this version, --value does.
	out := l.cscli("alerts", "list", "-a", "--value", ip, "-o", "json", "--limit", "0")
	if out == "" || out == "null" {
		return 0
	}
	var alerts []json.RawMessage
	if err := json.Unmarshal([]byte(out), &alerts); err != nil {
		l.t.Fatalf("decode alerts %q: %v", out, err)
	}
	return len(alerts)
}

// waitFor polls cond until it holds or the deadline passes.
func itWaitFor(t *testing.T, what string, cond func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		ok, state := cond()
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s (last state: %s)", what, state)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func itNear(got, want time.Duration) bool {
	d := got - want
	return d >= -itTolerance && d <= itTolerance
}

func TestCrowdSecIntegration(t *testing.T) {
	if os.Getenv("RAN_CROWDSEC_IT") == "" {
		t.Skip("set RAN_CROWDSEC_IT=1 to run the CrowdSec integration test (needs Docker)")
	}
	l := startLAPI(t)

	// Allowlist before any alert for that IP.
	const allowlisted = "1.0.0.1"
	l.cscli("allowlists", "create", "ran_it", "-d", "ran integration test")
	l.cscli("allowlists", "add", "ran_it", allowlisted)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cfg := CrowdSecConfig{
		URL:           l.url,
		MachineID:     itMachineID,
		Password:      itPassword,
		BanOn:         Classes, // probe too, so the profile has to filter it
		Cooldown:      0,
		BatchInterval: 0,
		BatchSize:     1,
	}
	a, err := NewCrowdSec(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), testMetrics(t))
	if err != nil {
		t.Fatalf("NewCrowdSec: %v", err)
	}
	defer a.Close()

	// push submits one event through the production sink. The sink is a single
	// FIFO worker with batch size 1, so when a later alert is visible every
	// earlier one has been processed.
	push := func(ip string, class Class) {
		t.Helper()
		a.Submit(ctx, Event{
			Class: class,
			Info: SessionInfo{
				SourceIP:     ip,
				Protocol:     "ssh",
				Transport:    TransportTCP,
				DestPort:     22,
				AuthAttempts: 1,
			},
			Meta: map[string]string{"username": "root"},
		})
	}
	pushAndStore := func(ip string, class Class, wantAlerts int) {
		t.Helper()
		push(ip, class)
		itWaitFor(t, fmt.Sprintf("%d stored alert(s) for %s", wantAlerts, ip), func() (bool, string) {
			n := l.alertCount(ip)
			return n >= wantAlerts, fmt.Sprintf("%d alerts", n)
		})
	}
	// barrier makes sure everything submitted before it was processed, also for
	// alerts the LAPI drops (allowlist), by waiting for a ban of a sentinel IP.
	sentinelN := 0
	barrier := func() {
		t.Helper()
		sentinelN++
		ip := fmt.Sprintf("2606:4700:4700::%d", 1110+sentinelN)
		push(ip, ClassAttack)
		itWaitFor(t, "sentinel ban "+ip, func() (bool, string) {
			ds := l.decisions(ip)
			return len(ds) > 0, fmt.Sprintf("%d decisions", len(ds))
		})
	}

	t.Run("scan is banned", func(t *testing.T) {
		const ip = "8.8.4.4"
		pushAndStore(ip, ClassScan, 1)
		ds := l.decisions(ip)
		if len(ds) != 1 || ds[0].Type != "ban" || ds[0].Origin != "crowdsec" || ds[0].Scope != "Ip" || ds[0].Value != ip {
			t.Fatalf("decisions for scan = %+v, want one crowdsec ban for %s", ds, ip)
		}
		if got := itMaxRemaining(t, ds); !itNear(got, time.Hour) {
			t.Errorf("scan ban %v, want about 1h", got)
		}
	})

	t.Run("attack escalates and caps", func(t *testing.T) {
		const ip = "9.9.9.9"
		// Prior decisions n give min(168, 3^n) hours: 1, 3, 9, 27, 81, 168, 168.
		steps := []time.Duration{1, 3, 9, 27, 81, 168, 168}
		var prev time.Duration
		for i, h := range steps {
			want := h * time.Hour
			pushAndStore(ip, ClassAttack, i+1)
			ds := l.decisions(ip)
			if len(ds) == 0 {
				t.Fatalf("alert %d: no decision", i+1)
			}
			for _, d := range ds {
				if d.Type != "ban" || d.Origin != "crowdsec" {
					t.Fatalf("alert %d: decision %+v, want a crowdsec ban", i+1, d)
				}
			}
			got := itMaxRemaining(t, ds)
			t.Logf("alert %d: %d decision(s), longest ban %v (want about %v)", i+1, len(ds), got.Round(time.Second), want)
			if !itNear(got, want) {
				t.Errorf("alert %d: ban %v, want about %v", i+1, got, want)
			}
			// Every alert adds a decision (observed with v1.8.1: older rows stay),
			// and at the cap the new 168h ban is renewed, never shorter than the
			// previous one (no tolerance: the new row has the full duration).
			if len(ds) != i+1 {
				t.Errorf("alert %d: %d decisions, want %d", i+1, len(ds), i+1)
			}
			if i > 0 && got < prev-5*time.Second { // jitter of the two reads
				t.Errorf("alert %d: ban %v shorter than the previous %v", i+1, got, prev)
			}
			prev = got
		}
	})

	t.Run("probe has no decision", func(t *testing.T) {
		const ip = "1.1.1.1"
		pushAndStore(ip, ClassProbe, 1)
		if ds := l.decisions(ip); len(ds) != 0 {
			t.Fatalf("probe created decisions: %+v", ds)
		}
	})

	t.Run("allowlisted source has no decision", func(t *testing.T) {
		push(allowlisted, ClassAttack)
		barrier()
		if ds := l.decisions(allowlisted); len(ds) != 0 {
			t.Fatalf("allowlisted source got decisions: %+v", ds)
		}
		if n := l.alertCount(allowlisted); n != 0 {
			t.Errorf("allowlisted source has %d stored alerts, want 0", n)
		}
	})
}

// itGenericProfile is the operator's own catch-all policy that follows the
// shipped profile. Without ran_noban it would ban a probe alert.
const itGenericProfile = `---
name: default_ip_remediation
filters:
  - Alert.Remediation == true && Alert.GetScope() == "Ip"
decisions:
  - type: ban
    scope: Ip
    duration: 4h
on_success: break
`
