package trap

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

// icsCase describes one new trap for the sensor interplay tests: a harmless
// request, an attacking request and a way to build the trap.
type icsCase struct {
	proto string
	build func(*config.Config, *metrics.Metrics, *Limiter, Reporter) Trap
	probe []byte
	raid  []byte
}

func icsHTTPRequest(body []byte) []byte {
	return []byte("POST /ipp/print HTTP/1.1\r\nHost: x\r\nContent-Type: application/ipp\r\nConnection: close\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\n\r\n" + string(body))
}

func icsCases() []icsCase {
	return []icsCase{
		{"s7comm", func(c *config.Config, m *metrics.Metrics, l *Limiter, r Reporter) Trap {
			return NewS7Comm(c, quietLogger(), m, l, r)
		}, s7CR(), s7JobReq(1, []byte{s7FuncWriteVar, 0, 0}, nil)},
		{"enip", func(c *config.Config, m *metrics.Metrics, l *Limiter, r Reporter) Trap {
			return NewENIP(c, quietLogger(), m, l, r)
		}, enipReq(enipListIdentity, 0, nil), enipReq(enipSendRRData, 0, []byte{1, 2, 3})},
		{"pjl", func(c *config.Config, m *metrics.Metrics, l *Limiter, r Reporter) Trap {
			return NewPJL(c, quietLogger(), m, l, r)
		}, []byte("@PJL INFO ID\r\n"), []byte("@PJL FSDIR NAME=\"0:\\\"\r\n")},
		{"ipp", func(c *config.Config, m *metrics.Metrics, l *Limiter, r Reporter) Trap {
			return NewIPP(c, quietLogger(), m, l, r)
		}, icsHTTPRequest(ippBody(ippOpGetPrinterAttrs, 1, "", nil)), icsHTTPRequest(ippBody(ippOpPrintJob, 1, "x", nil))},
	}
}

// sendBehindProxy sends data behind a PROXY header for source and reads until
// the trap closes the connection.
func sendBehindProxy(t *testing.T, addr, source string, data []byte) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "PROXY TCP4 %s 127.0.0.1 40000 80\r\n", source)
	_, _ = conn.Write(data)
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	_, _ = io.Copy(io.Discard, conn)
}

// An ignored source is served and logged but leaves no event, no scan entry and
// no probe entry; a neighbor outside the list is alerted.
func TestICSTrapsIgnoredSourceLeavesNoAlertOrState(t *testing.T) {
	for _, tc := range icsCases() {
		t.Run(tc.proto, func(t *testing.T) {
			m := metrics.New(prometheus.NewRegistry(), "test")
			cfg := ignoreTelnetConfig(10, "8.8.8.8")
			cfg.Addrs = map[string]string{tc.proto: "127.0.0.1:0"}
			sink := &captureSink{}
			sensor := alert.NewSensor(alert.SensorConfig{SummaryWindow: time.Hour, Metrics: m, IgnoreIPs: cfg.IgnoreIPs}, sink, quietLogger())
			defer sensor.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			addr := serveTrap(t, ctx, tc.build(cfg, m, NewLimiter(cfg.MaxSessions, cfg.MaxPerIP), sensor))

			sendBehindProxy(t, addr, "8.8.8.8", tc.probe)
			sendBehindProxy(t, addr, "8.8.8.8", tc.raid)
			waitFor(t, func() bool { return counterVal(t, m.IgnoredSessions, tc.proto) >= 2 })
			waitFor(t, func() bool { return gaugeVal(t, m.ActiveSessions, tc.proto) == 0 })

			if got := sink.sources(); len(got) != 0 {
				t.Fatalf("ignored source produced events: %v", got)
			}
			for _, name := range []string{"scan", "probe"} {
				if got := gaugeVal(t, m.TrackedEntries, name); got != 0 {
					t.Errorf("tracked %s entries = %v, want 0 for an ignored source", name, got)
				}
			}

			sendBehindProxy(t, addr, "8.8.4.4", tc.raid)
			waitFor(t, func() bool { return len(sink.sources()) >= 1 })
			if got := sink.sources(); got[0] != "8.8.4.4" {
				t.Errorf("event source = %v, want the neighbor 8.8.4.4", got)
			}
		})
	}
}

// A source that touches three of the new protocols is a scanner: the new
// protocol names count as distinct protocols for the scan rule.
func TestICSTrapsCountForScanDetection(t *testing.T) {
	m := metrics.New(prometheus.NewRegistry(), "test")
	cfg := ignoreTelnetConfig(10)
	sink := &captureSink{}
	sensor := alert.NewSensor(alert.SensorConfig{SummaryWindow: time.Hour, Metrics: m}, sink, quietLogger())
	defer sensor.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// One harmless request per protocol from the same (proxied) public source.
	for _, tc := range icsCases()[:3] {
		c := *cfg
		c.Addrs = map[string]string{tc.proto: "127.0.0.1:0"}
		addr := serveTrap(t, ctx, tc.build(&c, m, NewLimiter(c.MaxSessions, c.MaxPerIP), sensor))
		sendBehindProxy(t, addr, "8.8.4.4", tc.probe)
	}
	waitFor(t, func() bool {
		sink.mu.Lock()
		defer sink.mu.Unlock()
		for _, ev := range sink.events {
			if ev.Class == alert.ClassScan && ev.Info.SourceIP == "8.8.4.4" {
				return true
			}
		}
		return false
	})
}
