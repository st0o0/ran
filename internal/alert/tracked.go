package alert

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/st0o0/ran/internal/metrics"
)

// Tracking map names, used as the bounded "map" metric label.
const (
	mapScan     = "scan"
	mapProbe    = "probe"
	mapCooldown = "cooldown"
)

// trackStats reports the size and forced evictions of one bounded tracking map.
// A nil *trackStats is valid and does nothing, so trackers work without metrics.
type trackStats struct {
	entries   prometheus.Gauge
	evictions prometheus.Counter
}

func newTrackStats(m *metrics.Metrics, name string) *trackStats {
	if m == nil {
		return nil
	}
	return &trackStats{
		entries:   m.TrackedEntries.WithLabelValues(name),
		evictions: m.TrackedEvictions.WithLabelValues(name),
	}
}

func (t *trackStats) size(n int) {
	if t != nil {
		t.entries.Set(float64(n))
	}
}

// evicted counts a live (not yet expired) entry dropped because the map was full.
func (t *trackStats) evicted() {
	if t != nil {
		t.evictions.Inc()
	}
}
