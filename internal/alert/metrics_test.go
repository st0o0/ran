package alert

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestCrowdSecPushMetricsSuccess(t *testing.T) {
	srv := testServer(t, "ran", "secret", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	m := testMetrics(t)
	a, err := NewCrowdSec(context.Background(), testConfig(srv.URL), slog.Default(), m)
	if err != nil {
		t.Fatal(err)
	}
	a.Submit(context.Background(), ev("8.8.8.8", "ssh"))
	waitFor(t, "sent", func() bool { return pipelineCount(t, m, "ssh", "sent") >= 1 })
	a.Close()

	if n := histogramCount(t, m.CrowdSecPushDuration); n != 1 {
		t.Errorf("push duration observations = %d, want 1", n)
	}
	if v := metricValue(t, m.CrowdSecPushErrors); v != 0 {
		t.Errorf("push errors = %v, want 0", v)
	}
}

func TestCrowdSecPushMetricsFailure(t *testing.T) {
	setPacing(t, 10*time.Millisecond, time.Hour)
	srv := testServer(t, "ran", "secret", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	defer srv.Close()

	m := testMetrics(t)
	a, err := NewCrowdSec(context.Background(), testConfig(srv.URL), slog.Default(), m)
	if err != nil {
		t.Fatal(err)
	}
	a.Submit(context.Background(), ev("8.8.8.8", "ssh"))
	waitFor(t, "push error", func() bool { return metricValue(t, m.CrowdSecPushErrors) >= 1 })
	a.Close()
}

func TestCrowdSecQueueLengthGauge(t *testing.T) {
	release := make(chan struct{})
	srv := testServer(t, "ran", "secret", func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	m := testMetrics(t)
	a, err := NewCrowdSec(context.Background(), testConfig(srv.URL), slog.Default(), m)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		a.Submit(context.Background(), ev(wideIP(i), "ssh"))
	}
	// The worker is blocked in the first POST, so the rest waits in the queue.
	waitFor(t, "queued alerts", func() bool { return metricValue(t, m.CrowdSecQueueLength) >= 3 })
	close(release)
	waitFor(t, "queue drained", func() bool { return metricValue(t, m.CrowdSecQueueLength) == 0 })
	a.Close()
}

func TestTrackedMapMetrics(t *testing.T) {
	m := testMetrics(t)
	clock := newFakeClock()
	s := newSensor(SensorConfig{MaxTracked: 2, SummaryWindow: time.Minute, Metrics: m}, nil, slog.New(slog.NewJSONHandler(&lockedBuffer{}, nil)))
	s.scan.nowFunc = clock.Now
	s.probes.nowFunc = clock.Now

	for i := 0; i < 3; i++ {
		info := tcpInfo(wideIP(i), "ssh")
		s.SessionEnd(info)
	}
	if v := metricValue(t, m.TrackedEntries.WithLabelValues("scan")); v != 2 {
		t.Errorf("scan entries = %v, want 2 (capped)", v)
	}
	if v := metricValue(t, m.TrackedEntries.WithLabelValues("probe")); v != 2 {
		t.Errorf("probe entries = %v, want 2 (capped)", v)
	}
	if v := metricValue(t, m.TrackedEvictions.WithLabelValues("scan")); v != 1 {
		t.Errorf("scan evictions = %v, want 1", v)
	}
	if v := metricValue(t, m.TrackedEvictions.WithLabelValues("probe")); v != 1 {
		t.Errorf("probe evictions = %v, want 1", v)
	}
	if v := metricValue(t, m.ProbeSuppressed); v != 3 {
		t.Errorf("suppressed probe sessions = %v, want 3", v)
	}

	// Expired entries are cleaned up, not counted as evictions.
	clock.Advance(time.Hour)
	s.scan.cleanup()
	if v := metricValue(t, m.TrackedEntries.WithLabelValues("scan")); v != 0 {
		t.Errorf("scan entries after expiry = %v, want 0", v)
	}
	if v := metricValue(t, m.TrackedEvictions.WithLabelValues("scan")); v != 1 {
		t.Errorf("scan evictions after expiry = %v, want still 1", v)
	}
}

func TestCooldownMetrics(t *testing.T) {
	m := testMetrics(t)
	d := newCooldownFilter(time.Hour, 2)
	d.stats = newTrackStats(m, mapCooldown)
	for i := 0; i < 3; i++ {
		if _, _, ok := d.Allow(wideIP(i), ClassAttack); !ok {
			t.Fatal("allow failed")
		}
	}
	if v := metricValue(t, m.TrackedEntries.WithLabelValues("cooldown")); v != 2 {
		t.Errorf("cooldown entries = %v, want 2", v)
	}
	if v := metricValue(t, m.TrackedEvictions.WithLabelValues("cooldown")); v != 1 {
		t.Errorf("cooldown evictions = %v, want 1", v)
	}
}

// metricValue returns the current value of a counter or gauge.
func metricValue(t *testing.T, c prometheus.Metric) float64 {
	t.Helper()
	var out dto.Metric
	if err := c.Write(&out); err != nil {
		t.Fatal(err)
	}
	if out.Counter != nil {
		return out.GetCounter().GetValue()
	}
	return out.GetGauge().GetValue()
}

func histogramCount(t *testing.T, h prometheus.Metric) uint64 {
	t.Helper()
	var out dto.Metric
	if err := h.Write(&out); err != nil {
		t.Fatal(err)
	}
	return out.GetHistogram().GetSampleCount()
}
