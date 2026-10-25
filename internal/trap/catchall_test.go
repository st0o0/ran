package trap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"maps"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

func TestSniffProtocolTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{"tls 1.0 record", []byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01}, sniffTLS},
		{"tls 1.2 record", []byte{0x16, 0x03, 0x03, 0x00, 0x2f}, sniffTLS},
		{"tls record header only", []byte{0x16, 0x03, 0x01}, sniffTLS},
		{"tls wrong major", []byte{0x16, 0x02, 0x01}, sniffUnknown},
		{"tls wrong minor", []byte{0x16, 0x03, 0x09}, sniffUnknown},
		{"tls too short", []byte{0x16, 0x03}, sniffUnknown},
		{"http get", []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), sniffHTTP},
		{"http post", []byte("POST /a HTTP/1.0\r\n"), sniffHTTP},
		{"http connect", []byte("CONNECT 1.1.1.1:443 HTTP/1.1\r\n"), sniffHTTP},
		{"http2 preface", []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), sniffHTTP},
		{"http lowercase is unknown", []byte("get / HTTP/1.1\r\n"), sniffUnknown},
		{"method without space is unknown", []byte("GETX / HTTP/1.1"), sniffUnknown},
		{"smb1 over netbios", []byte{0x00, 0x00, 0x00, 0x2f, 0xff, 'S', 'M', 'B', 0x72}, sniffSMB},
		{"smb2 over netbios", []byte{0x00, 0x00, 0x00, 0x2f, 0xfe, 'S', 'M', 'B', 0x40}, sniffSMB},
		{"smb too short", []byte{0x00, 0x00, 0x00, 0x2f, 0xff, 'S', 'M'}, sniffUnknown},
		{"ssh banner", []byte("SSH-2.0-OpenSSH_9.6\r\n"), sniffSSH},
		{"ssh prefix only", []byte("SSH-"), sniffSSH},
		{"ssh without dash", []byte("SSH"), sniffUnknown},
		{"rdp x224 connection request", []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00}, sniffRDP},
		{"rdp wrong cr type", []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00}, sniffUnknown},
		{"rdp too short", []byte{0x03, 0x00, 0x00, 0x13, 0x0e}, sniffUnknown},
		{"binary junk", []byte{0xde, 0xad, 0xbe, 0xef}, sniffUnknown},
		{"single null", []byte{0x00}, sniffUnknown},
		{"empty", nil, sniffUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := sniffProtocol(tc.in); got != tc.want {
				t.Errorf("sniffProtocol(%x) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestPrintableTextIsSafe(t *testing.T) {
	t.Parallel()
	in := []byte("ab\x00\r\n\t\x7f\xff\xc3\xa9~ ")
	got := printableText(in)
	if got != "ab........~ " {
		t.Errorf("printableText = %q", got)
	}
	if len(got) != len(in) {
		t.Errorf("length %d, want %d", len(got), len(in))
	}
}

func catchallConfig(addrs string, timeout time.Duration, maxPerIP int) *config.Config {
	return &config.Config{
		Addrs:          map[string]string{"catchall": addrs},
		PerProto:       make(map[string]config.ProtoConfig),
		SessionTimeout: timeout,
		MaxSessions:    100,
		MaxPerIP:       maxPerIP,
	}
}

type catchallEnv struct {
	addr    string
	sink    *eventSink
	logs    *syncBuffer
	metrics *metrics.Metrics
	reg     *prometheus.Registry
}

// startCatchall starts a catchall trap behind a real sensor and returns the
// bound address.
func startCatchall(t *testing.T, window time.Duration, cfg *config.Config) catchallEnv {
	t.Helper()
	sink := &eventSink{}
	logs := &syncBuffer{}
	logger := newJSONLogger(logs)
	sensor := alert.NewSensor(alert.SensorConfig{SummaryWindow: time.Hour}, sink, logger)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	tr := NewCatchall(cfg, logger, m, NewLimiter(cfg.MaxSessions, cfg.MaxPerIP), sensor)
	tr.readWindow = window
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(sensor.Close)
	t.Cleanup(cancel)
	return catchallEnv{addr: serveTrap(t, ctx, tr), sink: sink, logs: logs, metrics: m, reg: reg}
}

// readAll reads until the server closes the connection. A reset (the server
// closed with unread input) ends the read like a close; a timeout fails.
func readAll(t *testing.T, c net.Conn) []byte {
	t.Helper()
	b, err := io.ReadAll(c)
	if err != nil && isTimeout(err) {
		t.Fatalf("read: %v", err)
	}
	return b
}

func logLines(t *testing.T, logs *syncBuffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		if l == "" {
			continue
		}
		m := map[string]any{}
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("bad log line %q: %v", l, err)
		}
		out = append(out, m)
	}
	return out
}

func waitLog(t *testing.T, logs *syncBuffer, pred func(map[string]any) bool) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, l := range logLines(t, logs) {
			if pred(l) {
				return l
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("log line not found in %s", logs.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestCatchallLogsFirst256BytesOfLargerSend(t *testing.T) {
	SetPasswordLogMode("on")
	t.Cleanup(func() { SetPasswordLogMode("off") })
	env := startCatchall(t, 2*time.Second, catchallConfig("127.0.0.1:0", 5*time.Second, 10))
	data := append([]byte{0x16, 0x03, 0x01}, bytes.Repeat([]byte{'A'}, 297)...) // 300 bytes
	c := dialTrap(t, env.addr)
	if _, err := c.Write(data); err != nil {
		t.Fatal(err)
	}
	// The trap never answers: the connection is closed without any byte.
	if got := readAll(t, c); len(got) != 0 {
		t.Errorf("trap sent %d bytes, want none", len(got))
	}

	line := waitLog(t, env.logs, func(m map[string]any) bool { return m["action"] == "payload" })
	if line["payload_type"] != "catchall" || line["sniffed_protocol"] != "tls" {
		t.Errorf("payload line = %v", line)
	}
	if h, _ := line["hex"].(string); h != hex.EncodeToString(data[:256]) {
		t.Errorf("hex has %d chars, want the first 256 bytes (%d chars)", len(h), 512)
	}
	if txt, _ := line["text"].(string); len(txt) != 256 || strings.ContainsAny(txt, "\x00\r\n") {
		t.Errorf("text = %q", txt)
	}
	if line["bytes"] != float64(256) {
		t.Errorf("bytes = %v, want 256", line["bytes"])
	}

	evs := env.sink.waitEvents(t, func(e []alert.Event) bool { return hasClass(e, alert.ClassAttack) })
	var meta map[string]string
	for _, e := range evs {
		if e.Class == alert.ClassAttack {
			meta = e.Meta
		}
	}
	if want := map[string]string{"sniffed_protocol": "tls", "bytes": "256"}; !maps.Equal(meta, want) {
		t.Errorf("alert meta = %v", meta)
	}
	if got := counterVal(t, env.metrics.Connections, "catchall", "completed"); got != 1 {
		// The session ends after the read; wait for it.
		time.Sleep(100 * time.Millisecond)
		if got = counterVal(t, env.metrics.Connections, "catchall", "completed"); got != 1 {
			t.Errorf("connections{catchall,completed} = %v", got)
		}
	}
}

func TestCatchallSniffLabelsOnTheWire(t *testing.T) {
	t.Parallel()
	cases := map[string][]byte{
		"http":    []byte("GET /admin HTTP/1.1\r\n\r\n"),
		"ssh":     []byte("SSH-2.0-libssh\r\n"),
		"smb":     {0, 0, 0, 0x10, 0xff, 'S', 'M', 'B', 0x72, 0, 0, 0, 0},
		"rdp":     {3, 0, 0, 0x13, 0x0e, 0xe0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0},
		"unknown": {1, 2, 3, 4, 5},
	}
	for want, data := range cases {
		t.Run(want, func(t *testing.T) {
			t.Parallel()
			env := startCatchall(t, 2*time.Second, catchallConfig("127.0.0.1:0", 5*time.Second, 10))
			c := dialTrap(t, env.addr)
			if _, err := c.Write(data); err != nil {
				t.Fatal(err)
			}
			line := waitLog(t, env.logs, func(m map[string]any) bool { return m["action"] == "payload" })
			if line["sniffed_protocol"] != want {
				t.Errorf("label = %v, want %s", line["sniffed_protocol"], want)
			}
		})
	}
}

func TestCatchallSilentConnectIsProbe(t *testing.T) {
	t.Parallel()
	env := startCatchall(t, 150*time.Millisecond, catchallConfig("127.0.0.1:0", 5*time.Second, 10))
	start := time.Now()
	c := dialTrap(t, env.addr)
	if got := readAll(t, c); len(got) != 0 {
		t.Errorf("trap sent %d bytes to a silent client", len(got))
	}
	if d := time.Since(start); d < 100*time.Millisecond || d > 3*time.Second {
		t.Errorf("closed after %v, want about the 150ms read window", d)
	}
	if got := env.sink.waitOutcome(t); got != alert.ClassProbe {
		t.Errorf("silent connect class = %s, want probe", got)
	}
	if hasClass(env.sink.snapshot(), alert.ClassAttack) {
		t.Error("silent connect produced an attack")
	}
	waitFor(t, func() bool { return counterVal(t, env.metrics.Connections, "catchall", "probe") == 1 })
}

func TestCatchallClientCloseWithoutDataIsProbe(t *testing.T) {
	t.Parallel()
	env := startCatchall(t, 2*time.Second, catchallConfig("127.0.0.1:0", 5*time.Second, 10))
	c := dialTrap(t, env.addr)
	c.Close()
	if got := env.sink.waitOutcome(t); got != alert.ClassProbe {
		t.Errorf("class = %s, want probe", got)
	}
}

// The read window never outlasts the session timeout.
func TestCatchallReadWindowIsCutToSessionTimeout(t *testing.T) {
	t.Parallel()
	env := startCatchall(t, time.Hour, catchallConfig("127.0.0.1:0", 300*time.Millisecond, 10))
	start := time.Now()
	c := dialTrap(t, env.addr)
	readAll(t, c)
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("connection stayed open for %v with a 300ms session timeout", d)
	}
}

func TestCatchallListensOnEveryConfiguredAddress(t *testing.T) {
	t.Parallel()
	var addrs [2]string
	for i := range addrs {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addrs[i] = l.Addr().String()
		l.Close()
	}
	env := startCatchall(t, 2*time.Second, catchallConfig(addrs[0]+","+addrs[1], 5*time.Second, 10))
	_ = env
	for _, a := range addrs {
		c := dialTrap(t, a)
		if _, err := c.Write([]byte("GET / HTTP/1.1\r\n")); err != nil {
			t.Fatal(err)
		}
		want := a
		waitLog(t, env.logs, func(m map[string]any) bool {
			return m["action"] == "payload" && m["dest_port"] == float64(portOf(want))
		})
	}
}

func portOf(addr string) int {
	_, p := ParseAddr(addr)
	return p
}

// Excess connections from one source are rejected before a goroutine exists.
func TestCatchallFloodIsRejected(t *testing.T) {
	t.Parallel()
	env := startCatchall(t, 10*time.Second, catchallConfig("127.0.0.1:0", 20*time.Second, 1))
	first := dialTrap(t, env.addr) // holds the only slot
	_ = first
	second := dialTrap(t, env.addr)
	if got := readAll(t, second); len(got) != 0 {
		t.Errorf("rejected connection received %d bytes", len(got))
	}
	waitFor(t, func() bool { return counterVal(t, env.metrics.SessionsRejected, "catchall") >= 1 })
}

// Port-based scan detection works on the real destination port: a source that
// touches five catchall ports becomes a scan. The source is given through the
// PROXY protocol because loopback is never classified as a scanner.
func TestCatchallPortsCountForScanDetection(t *testing.T) {
	t.Parallel()
	addrs := make([]string, 5)
	for i := range addrs {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addrs[i] = l.Addr().String()
		l.Close()
	}
	cfg := catchallConfig(strings.Join(addrs, ","), 5*time.Second, 10)
	cfg.ProxyProtocol = true
	cfg.ProxyTrusted = loopbackPrefixes
	env := startCatchall(t, 2*time.Second, cfg)
	for _, a := range addrs {
		c := dialTrap(t, a)
		if _, err := c.Write([]byte("PROXY TCP4 8.8.8.8 1.1.1.1 40000 80\r\n\x01\x02\x03")); err != nil {
			t.Fatal(err)
		}
		readAll(t, c)
	}
	env.sink.waitEvents(t, func(e []alert.Event) bool { return hasClass(e, alert.ClassScan) })
}

// Both new traps are distinct protocols for the breadth rule, with the fixed labels.
func TestCatchallAndBannerAreScanProtocols(t *testing.T) {
	t.Parallel()
	sink := &eventSink{}
	sensor := alert.NewSensor(alert.SensorConfig{SummaryWindow: time.Hour}, sink, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer sensor.Close()
	var last alert.Class
	for _, proto := range []string{"catchall", "banner", "ssh"} {
		last = sensor.Alert(context.Background(), alert.SessionInfo{
			SourceIP: "8.8.8.8", Protocol: proto, Transport: alert.TransportTCP, DestPort: 9000, PayloadBytes: 1,
		}, nil)
	}
	if last != alert.ClassScan {
		t.Errorf("class after catchall, banner and ssh = %s, want scan", last)
	}
}

func TestCatchallMetricLabelIsFixed(t *testing.T) {
	t.Parallel()
	env := startCatchall(t, 2*time.Second, catchallConfig("127.0.0.1:0", 5*time.Second, 10))
	c := dialTrap(t, env.addr)
	_, _ = c.Write([]byte("GET /\x00evil HTTP/1.1\r\n"))
	waitFor(t, func() bool { return counterVal(t, env.metrics.Connections, "catchall", "completed") == 1 })
	families, err := env.reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "protocol" && l.GetValue() != "catchall" {
					t.Errorf("metric %s has protocol label %q", f.GetName(), l.GetValue())
				}
			}
		}
	}
}

// An ignored source is served and logged with ignored=true but never reported.
func TestCatchallIgnoredSourceNeverAlerts(t *testing.T) {
	t.Parallel()
	cfg := catchallConfig("127.0.0.1:0", 5*time.Second, 10)
	cfg.ProxyProtocol = true
	cfg.ProxyTrusted = loopbackPrefixes
	sink := &eventSink{}
	logs := &syncBuffer{}
	logger := newJSONLogger(logs)
	prefixes, err := config.ParseIgnoreList("RAN_IGNORE_IPS", "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	sensor := alert.NewSensor(alert.SensorConfig{SummaryWindow: time.Hour, IgnoreIPs: prefixes}, sink, logger)
	defer sensor.Close()
	tr := NewCatchall(cfg, logger, metrics.New(prometheus.NewRegistry(), "test"), NewLimiter(10, 10), sensor)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := serveTrap(t, ctx, tr)

	c := dialTrap(t, addr)
	if _, err := c.Write([]byte("PROXY TCP4 8.8.8.8 1.1.1.1 40000 80\r\nGET / HTTP/1.1\r\n")); err != nil {
		t.Fatal(err)
	}
	waitLog(t, logs, func(m map[string]any) bool { return m["action"] == "payload" && m["ignored"] == true })
	time.Sleep(100 * time.Millisecond)
	if evs := sink.snapshot(); len(evs) != 0 {
		t.Errorf("ignored source produced events: %+v", evs)
	}
}

// The raw bytes reach the log only in mode "on". The alert meta never carries
// them in any mode and holds exactly the label and the byte count.
func TestCatchallLogsFollowPasswordMode(t *testing.T) {
	secret := "hunter2-secret-token"
	data := []byte("GET / HTTP/1.1\r\nAuthorization: Basic " + secret + "\r\n\r\n")
	sum := sha256.Sum256(data)
	prefix := hex.EncodeToString(sum[:])[:8]
	masked := "*** (" + strconv.Itoa(len(data)) + ")"
	defer SetPasswordLogMode("off")

	for _, mode := range []string{"off", "mask", "on"} {
		t.Run(mode, func(t *testing.T) {
			SetPasswordLogMode(mode)
			env := startCatchall(t, 2*time.Second, catchallConfig("127.0.0.1:0", 5*time.Second, 10))
			c := dialTrap(t, env.addr)
			if _, err := c.Write(data); err != nil {
				t.Fatal(err)
			}
			line := waitLog(t, env.logs, func(m map[string]any) bool { return m["action"] == "payload" })
			evs := env.sink.waitEvents(t, func(e []alert.Event) bool { return hasClass(e, alert.ClassAttack) })
			for _, e := range evs {
				if e.Class != alert.ClassAttack {
					continue
				}
				want := map[string]string{"sniffed_protocol": "http", "bytes": strconv.Itoa(len(data))}
				if !maps.Equal(e.Meta, want) {
					t.Errorf("alert meta = %v, want exactly %v", e.Meta, want)
				}
			}
			all := env.logs.String()
			switch mode {
			case "on":
				if line["hex"] != hex.EncodeToString(data) || !strings.Contains(line["text"].(string), secret) {
					t.Errorf("mode on: line = %v", line)
				}
			default:
				for _, raw := range []string{secret, hex.EncodeToString([]byte(secret)), "Authorization", hex.EncodeToString(data)} {
					if strings.Contains(all, raw) {
						t.Errorf("mode %s: %q appears in log %s", mode, raw, all)
					}
				}
				if line["sha256_prefix"] != prefix {
					t.Errorf("sha256_prefix = %v, want %s", line["sha256_prefix"], prefix)
				}
				if line["sniffed_protocol"] != "http" || line["bytes"] != float64(len(data)) {
					t.Errorf("line = %v", line)
				}
				if mode == "off" {
					if _, ok := line["hex"]; ok {
						t.Errorf("hex present in mode off: %v", line)
					}
					if _, ok := line["text"]; ok {
						t.Errorf("text present in mode off: %v", line)
					}
				} else if line["hex"] != masked || line["text"] != masked {
					t.Errorf("mode mask: hex/text = %v / %v, want %s", line["hex"], line["text"], masked)
				}
			}
		})
	}
}
