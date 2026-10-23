package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestNew(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg, "test")

	if m.Connections == nil {
		t.Error("Connections is nil")
	}
	if m.CredentialsCaptured == nil {
		t.Error("CredentialsCaptured is nil")
	}
	if m.ActiveSessions == nil {
		t.Error("ActiveSessions is nil")
	}
	if m.SessionDuration == nil {
		t.Error("SessionDuration is nil")
	}
	if m.CrowdSecPipeline == nil {
		t.Error("CrowdSecPipeline is nil")
	}
	if m.CrowdSecDropped == nil {
		t.Error("CrowdSecDropped is nil")
	}

	if _, err := reg.Gather(); err != nil {
		t.Fatalf("gather error: %v", err)
	}

	m.Connections.WithLabelValues("ssh", "completed").Inc()
	m.CredentialsCaptured.WithLabelValues("ssh").Inc()
	m.ActiveSessions.WithLabelValues("ssh").Set(1)
	m.SessionDuration.WithLabelValues("ssh").Observe(1.5)
	m.CrowdSecPipeline.WithLabelValues("ssh", "sent").Inc()
	m.CrowdSecDropped.WithLabelValues("ssh").Inc()

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather error: %v", err)
	}
	if len(families) < 5 {
		t.Errorf("got %d metric families, want at least 5", len(families))
	}
}

func TestNewSeparateRegistries(t *testing.T) {
	reg1 := prometheus.NewRegistry()
	reg2 := prometheus.NewRegistry()

	m1 := New(reg1, "test")
	m2 := New(reg2, "test")

	if m1 == nil || m2 == nil {
		t.Fatal("New should not return nil")
	}
}

func TestMetricNamesAndStagesUnchanged(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg, "test")

	m.Connections.WithLabelValues("ssh", "completed").Inc()
	m.CredentialsCaptured.WithLabelValues("ssh").Inc()
	m.ActiveSessions.WithLabelValues("ssh").Inc()
	m.SessionDuration.WithLabelValues("ssh").Observe(1)
	m.CrowdSecDropped.WithLabelValues("ssh").Inc()
	for _, stage := range []string{"received", "invalid", "closed", "filtered", "cooldown", "queued", "sent", "failed", "released", "dropped"} {
		m.CrowdSecPipeline.WithLabelValues("ssh", stage).Inc()
	}

	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	labels := map[string][]string{}
	stages := map[string]bool{}
	for _, f := range families {
		for _, metric := range f.GetMetric() {
			var names []string
			for _, l := range metric.GetLabel() {
				names = append(names, l.GetName())
				if f.GetName() == "ran_crowdsec_pipeline_total" && l.GetName() == "stage" {
					stages[l.GetValue()] = true
				}
			}
			labels[f.GetName()] = names
		}
	}
	want := map[string][]string{
		"ran_connections_total":             {"outcome", "protocol"},
		"ran_credentials_captured_total":    {"protocol"},
		"ran_active_sessions":               {"protocol"},
		"ran_session_duration_seconds":      {"protocol"},
		"ran_crowdsec_pipeline_total":       {"protocol", "stage"},
		"ran_crowdsec_alerts_dropped_total": {"protocol"},
	}
	for name, ls := range want {
		got, ok := labels[name]
		if !ok {
			t.Errorf("metric %s missing", name)
			continue
		}
		if len(got) != len(ls) || got[0] != ls[0] || (len(ls) > 1 && got[1] != ls[1]) {
			t.Errorf("%s labels = %v, want %v", name, got, ls)
		}
	}
	for _, s := range []string{"cooldown", "filtered", "invalid", "closed", "released"} {
		if !stages[s] {
			t.Errorf("stage %q not emitted", s)
		}
	}
	for _, s := range []string{"cached", "deduplicated"} {
		if stages[s] {
			t.Errorf("removed stage %q still emitted", s)
		}
	}
}

func TestNewMetricsRoundThree(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg, "test")

	m.CrowdSecPushDuration.Observe(0.2)
	m.CrowdSecPushErrors.Inc()
	m.CrowdSecQueueLength.Set(3)
	m.TrackedEntries.WithLabelValues("scan").Set(1)
	m.TrackedEvictions.WithLabelValues("probe").Inc()
	m.ProbeSuppressed.Inc()
	m.SessionsRejected.WithLabelValues("ssh").Inc()
	m.SessionDuration.WithLabelValues("ssh").Observe(100)

	want := map[string]bool{
		"ran_crowdsec_push_duration_seconds":          false,
		"ran_crowdsec_push_errors_total":              false,
		"ran_crowdsec_queue_length":                   false,
		"ran_tracked_entries":                         false,
		"ran_tracked_evictions_total":                 false,
		"ran_probe_summary_suppressed_sessions_total": false,
		"ran_sessions_rejected_total":                 false,
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if _, ok := want[f.GetName()]; ok {
			want[f.GetName()] = true
		}
		if f.GetName() == "ran_session_duration_seconds" {
			b := f.GetMetric()[0].GetHistogram().GetBucket()
			if first, last := b[0].GetUpperBound(), b[len(b)-1].GetUpperBound(); first != 0.1 || last != 120 {
				t.Errorf("session duration buckets %v..%v, want 0.1..120", first, last)
			}
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("metric %s not exposed", name)
		}
	}
}
