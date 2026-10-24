package alert

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func ignoreSensor(t *testing.T, ranges ...string) (*Sensor, *recordingSink, *fakeClock, *lockedBuffer) {
	t.Helper()
	s, sink, clk, buf := testSensor(t, time.Minute, 100)
	for _, r := range ranges {
		s.ignore = append(s.ignore, netip.MustParsePrefix(r))
	}
	return s, sink, clk, buf
}

func TestIgnoredAttackProbeAndScanProduceNothing(t *testing.T) {
	s, sink, clk, buf := ignoreSensor(t, "8.8.8.8/32", "2606:4700:4700::/48")
	ctx := context.Background()

	for _, ip := range []string{"8.8.8.8", "::ffff:8.8.8.8", "2606:4700:4700::1111"} {
		// attack
		attack := tcpInfo(ip, "ssh")
		attack.AuthAttempts = 1
		if got := s.Alert(ctx, attack, map[string]string{"username": "root"}); got != "" {
			t.Errorf("%s: Alert class = %q, want empty", ip, got)
		}
		if s.SessionEnd(attack) {
			t.Errorf("%s: attack SessionEnd aggregated the log, want false", ip)
		}
		// probe: SessionEnd must not feed the probe summary
		if s.SessionEnd(tcpInfo(ip, "redis")) {
			t.Errorf("%s: probe SessionEnd aggregated the log, want false", ip)
		}
		// scan: three protocols within the window
		for _, proto := range []string{"ssh", "redis", "vnc", "ftp"} {
			info := tcpInfo(ip, proto)
			info.Commands = 1
			s.Alert(ctx, info, nil)
			s.SessionEnd(info)
			clk.Advance(time.Second)
		}
	}

	if n := len(sink.snapshot()); n != 0 {
		t.Errorf("sink got %d events, want 0", n)
	}
	if n := s.scan.len(); n != 0 {
		t.Errorf("scan tracker holds %d entries, want 0", n)
	}
	s.probes.mu.Lock()
	n := len(s.probes.entries)
	s.probes.mu.Unlock()
	if n != 0 {
		t.Errorf("probe log holds %d entries, want 0", n)
	}
	clk.Advance(time.Hour)
	s.probes.flushDue()
	if strings.Contains(buf.String(), "probe summary") {
		t.Errorf("ignored source appeared in a probe summary: %s", buf.String())
	}
}

func TestIgnoredNeighborStillAlerts(t *testing.T) {
	s, sink, _, _ := ignoreSensor(t, "8.8.8.8/32")
	ctx := context.Background()

	for _, ip := range []string{"8.8.8.8", "8.8.4.4"} {
		info := tcpInfo(ip, "ssh")
		info.AuthAttempts = 1
		s.Alert(ctx, info, nil)
	}
	evs := sink.snapshot()
	if len(evs) != 1 || evs[0].Info.SourceIP != "8.8.4.4" || evs[0].Class != ClassAttack {
		t.Fatalf("events = %+v, want one attack from 8.8.4.4", evs)
	}

	// The neighbor is still tracked as a scanner and summarized as a probe.
	s2, sink2, _, _ := ignoreSensor(t, "8.8.8.8/32")
	for _, proto := range []string{"ssh", "redis", "vnc"} {
		info := tcpInfo("8.8.4.4", proto)
		info.AuthAttempts = 1
		s2.Alert(ctx, info, nil)
	}
	evs = sink2.snapshot()
	if len(evs) != 3 || evs[2].Class != ClassScan {
		t.Fatalf("events = %+v, want the third to be a scan", evs)
	}
	if !s2.SessionEnd(tcpInfo("1.1.1.1", "ssh")) {
		t.Error("non-ignored probe must still be summarized")
	}
}

func TestIgnoredMappedPeer(t *testing.T) {
	s, sink, _, _ := ignoreSensor(t, "8.8.8.8/32")
	info := tcpInfo("::ffff:8.8.8.8", "ssh")
	info.AuthAttempts = 1
	s.Alert(context.Background(), info, nil)
	if !s.Ignored("::ffff:8.8.8.8") || len(sink.snapshot()) != 0 {
		t.Errorf("mapped peer must be ignored, events = %v", sink.snapshot())
	}
}

func TestIgnoreListEmptyIgnoresNothing(t *testing.T) {
	s, _, _, _ := testSensor(t, 0, 10)
	if s.Ignored("8.8.8.8") {
		t.Error("empty list ignored a source")
	}
}
