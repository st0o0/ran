package alert

import (
	"context"
	"testing"
	"time"
)

func portInfo(ip, proto string, port int) SessionInfo {
	info := tcpInfo(ip, proto)
	info.DestPort = port
	return info
}

func TestScanByDistinctPorts(t *testing.T) {
	s, _, clk, _ := testSensor(t, time.Minute, 100)
	ctx := context.Background()
	for i, port := range []int{8081, 8082, 8083, 8084, 8085} {
		got := s.Alert(ctx, portInfo("8.8.8.8", "http", port), nil)
		want := ClassProbe
		if i == 4 {
			want = ClassScan
		}
		if got != want {
			t.Errorf("session %d class = %q, want %q", i+1, got, want)
		}
		clk.Advance(time.Second)
	}
}

func TestScanSamePortRepeated(t *testing.T) {
	s, _, _, _ := testSensor(t, time.Minute, 100)
	for i := range 50 {
		if got := s.Alert(context.Background(), portInfo("8.8.8.8", "http", 8081), nil); got == ClassScan {
			t.Fatalf("session %d classified scan on a single port", i)
		}
	}
}

func TestScanPortsWindowExpiry(t *testing.T) {
	s, _, clk, _ := testSensor(t, time.Minute, 100)
	ctx := context.Background()
	for _, port := range []int{1, 2, 3, 4} {
		s.Alert(ctx, portInfo("8.8.8.8", "http", port), nil)
		clk.Advance(3 * time.Minute)
	}
	// The first two ports are older than the window now.
	if got := s.Alert(ctx, portInfo("8.8.8.8", "http", 5), nil); got == ClassScan {
		t.Errorf("class = scan with only 3 live ports")
	}
}

func TestScanPortsIgnoreUDPAndIgnoredSources(t *testing.T) {
	s, sink, _, _ := ignoreSensor(t, "1.1.1.1/32")
	ctx := context.Background()
	for _, port := range []int{1, 2, 3, 4, 5, 6} {
		udp := portInfo("8.8.8.8", "dns", port)
		udp.Transport = TransportUDP
		s.Alert(ctx, udp, nil)

		ign := portInfo("1.1.1.1", "http", port)
		ign.Commands = 1
		s.Alert(ctx, ign, nil)
		s.SessionEnd(ign)
	}
	if n := s.scan.len(); n != 0 {
		t.Errorf("scan tracker holds %d entries, want 0", n)
	}
	if n := len(sink.snapshot()); n != 0 {
		t.Errorf("sink got %d events, want 0", n)
	}
}

func TestScanPortSetStaysBounded(t *testing.T) {
	tr := newScanTracker(scanWindow, scanProtocols, 10)
	clk := newFakeClock()
	tr.nowFunc = clk.Now
	// portLimit above the cap keeps the verdict false so the bound is observable.
	tr.portLimit = maxScanPorts + 1
	for port := 1; port <= 1000; port++ {
		tr.TouchPort("8.8.8.8", "http", port)
	}
	tr.mu.Lock()
	n := len(tr.entries["8.8.8.8"].Value.(*scanEntry).ports)
	tr.mu.Unlock()
	if n > maxScanPorts {
		t.Errorf("port set holds %d ports, want at most %d", n, maxScanPorts)
	}
}

func TestScanPortsEntryEviction(t *testing.T) {
	tr := newScanTracker(scanWindow, scanProtocols, 2)
	clk := newFakeClock()
	tr.nowFunc = clk.Now
	tr.TouchPort("8.8.8.8", "http", 1)
	tr.TouchPort("1.1.1.1", "http", 1)
	tr.TouchPort("2606:4700:4700::1111", "http", 1)
	if n := tr.len(); n != 2 {
		t.Errorf("entries = %d, want 2", n)
	}
}
