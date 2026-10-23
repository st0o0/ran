package alert

import (
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"
)

// capIP returns a distinct public-looking IPv4 address for every i below 2^24.
func capIP(i int) string {
	return fmt.Sprintf("11.%d.%d.%d", (i>>16)&255, (i>>8)&255, i&255)
}

// TestTrackedStructuresStayAtMaxTracked floods the three tracking structures
// (scan tracker, probe log, cooldown filter) with more unique sources than the
// cap and checks that each map and its FIFO list stay exactly at the cap. The
// cap is 100k here (production default is 20k) so the check covers a realistic
// number of entries without the cost of millions.
func TestTrackedStructuresStayAtMaxTracked(t *testing.T) {
	const maxTracked = 100_000
	const sources = maxTracked + maxTracked/2

	clk := newFakeClock()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	s := newSensor(SensorConfig{MaxTracked: maxTracked, SummaryWindow: time.Hour}, nil, logger)
	s.scan.nowFunc = clk.Now
	s.probes.nowFunc = clk.Now

	cd := newCooldownFilter(time.Hour, maxTracked)
	cd.nowFunc = clk.Now

	for i := 0; i < sources; i++ {
		ip := capIP(i)
		// One TCP protocol per source: touches the scan tracker and, as a pure
		// probe, the probe log.
		s.SessionEnd(tcpInfo(ip, "vnc"))
		cd.Allow(ip, ClassAttack)
		if i%1000 == 0 {
			clk.Advance(time.Second) // keep every entry inside its window
		}
	}

	s.scan.mu.Lock()
	scanMap, scanList := len(s.scan.entries), s.scan.order.Len()
	s.scan.mu.Unlock()
	s.probes.mu.Lock()
	probeMap, probeList := len(s.probes.entries), s.probes.order.Len()
	s.probes.mu.Unlock()
	cd.mu.Lock()
	cdMap, cdList := len(cd.seen), cd.order.Len()
	cd.mu.Unlock()

	for _, c := range []struct {
		name      string
		size, ord int
	}{
		{"scan", scanMap, scanList},
		{"probe", probeMap, probeList},
		{"cooldown", cdMap, cdList},
	} {
		if c.size != maxTracked || c.ord != maxTracked {
			t.Errorf("%s: map %d / list %d, want both %d", c.name, c.size, c.ord, maxTracked)
		}
	}
}
