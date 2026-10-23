package trap

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

type recordedAlert struct {
	IP       string
	Protocol string
	Meta     map[string]string
}

type recordingAlerter struct {
	mu     sync.Mutex
	alerts []recordedAlert
}

func (r *recordingAlerter) Alert(_ context.Context, ip, protocol string, meta map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.alerts = append(r.alerts, recordedAlert{ip, protocol, meta})
}

func (r *recordingAlerter) Close() {}

func (r *recordingAlerter) snapshot() []recordedAlert {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recordedAlert(nil), r.alerts...)
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newJSONLogger(buf io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// --- HTTP ---

func postHTTP(t *testing.T, cfg *config.Config, body string, headers map[string]string) {
	t.Helper()
	req, err := http.NewRequest("POST", "http://"+cfg.TrapAddr("http")+"/admin", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func startHTTPForTest(t *testing.T) (*config.Config, *recordingAlerter, *syncBuffer) {
	t.Helper()
	cfg := httpTestConfig(t)
	rec := &recordingAlerter{}
	logs := &syncBuffer{}
	m := metrics.New(prometheus.NewRegistry(), "test")
	tr := NewHTTP(cfg, newJSONLogger(logs), m, NewLimiter(cfg.MaxSessions, cfg.MaxPerIP), rec)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = tr.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)
	return cfg, rec, logs
}

func TestHTTPAlertUsesPeerNotForwardedHeader(t *testing.T) {
	cfg, rec, logs := startHTTPForTest(t)
	postHTTP(t, cfg, "username=a&password=b", map[string]string{"X-Forwarded-For": "203.0.113.9, 198.51.100.1"})

	alerts := rec.snapshot()
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}
	if alerts[0].IP != "127.0.0.1" {
		t.Errorf("alert IP = %q, want the socket peer 127.0.0.1", alerts[0].IP)
	}
	if !strings.Contains(logs.String(), `"claimed_client_ip":"203.0.113.9"`) {
		t.Errorf("log missing claimed_client_ip: %s", logs.String())
	}
	if strings.Contains(logs.String(), `"client_ip"`) {
		t.Error("legacy client_ip field must not be logged")
	}
}

func TestHTTPAlertIgnoresRealIPHeader(t *testing.T) {
	cfg, rec, _ := startHTTPForTest(t)
	postHTTP(t, cfg, "username=a&password=b", map[string]string{"X-Real-IP": "198.51.100.7"})
	alerts := rec.snapshot()
	if len(alerts) != 1 || alerts[0].IP != "127.0.0.1" {
		t.Fatalf("alerts = %+v, want one alert for the peer", alerts)
	}
}

func TestHTTPGarbageHeader(t *testing.T) {
	cfg, rec, logs := startHTTPForTest(t)
	postHTTP(t, cfg, "username=a&password=b", map[string]string{"X-Real-IP": "not-an-ip"})
	alerts := rec.snapshot()
	if len(alerts) != 1 || alerts[0].IP != "127.0.0.1" {
		t.Fatalf("alerts = %+v, want one alert for the peer", alerts)
	}
	if strings.Contains(logs.String(), "claimed_client_ip") {
		t.Error("garbage header must not be logged as claimed_client_ip")
	}
}

func TestHTTPOversizedBody(t *testing.T) {
	cfg, rec, _ := startHTTPForTest(t)
	postHTTP(t, cfg, "username=admin&password="+strings.Repeat("A", 200<<10), nil)
	alerts := rec.snapshot()
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}
	if alerts[0].Meta["username"] != "" || alerts[0].Meta["password"] != "" {
		t.Errorf("credentials from oversized body should be empty, got %+v", alerts[0].Meta)
	}
}

func TestHTTPBodyWithinLimit(t *testing.T) {
	cfg, rec, _ := startHTTPForTest(t)
	postHTTP(t, cfg, "username=admin&password=pw", nil)
	alerts := rec.snapshot()
	if len(alerts) != 1 || alerts[0].Meta["username"] != "admin" {
		t.Fatalf("alerts = %+v, want username admin", alerts)
	}
}

// --- Password logging ---

func TestPasswordLogModes(t *testing.T) {
	defer SetPasswordLogMode("off")
	cases := []struct {
		mode    string
		present bool
		want    string
	}{
		{"", false, ""},
		{"off", false, ""},
		{"mask", true, "*** (7)"},
		{"on", true, "hunter2"},
	}
	for _, tc := range cases {
		t.Run("mode="+tc.mode, func(t *testing.T) {
			SetPasswordLogMode(tc.mode)
			buf := &syncBuffer{}
			sess := NewSession("telnet", "tcp", "192.0.2.1", 1234, 23, newJSONLogger(buf))
			sess.LogAuthAttempt(slog.String("username", "root"), slog.String("password", "hunter2"))

			var rec map[string]any
			if err := json.Unmarshal([]byte(buf.String()), &rec); err != nil {
				t.Fatal(err)
			}
			if rec["username"] != "root" {
				t.Errorf("username = %v, want root", rec["username"])
			}
			got, ok := rec["password"]
			if ok != tc.present {
				t.Fatalf("password present = %v, want %v", ok, tc.present)
			}
			if ok && got != tc.want {
				t.Errorf("password = %v, want %q", got, tc.want)
			}
		})
	}
}

// --- Bounded line reads ---

func TestReadLineLimited(t *testing.T) {
	r := bufio.NewReaderSize(strings.NewReader("hello\r\nrest"), 16)
	line, err := readLineLimited(r, 32)
	if err != nil || line != "hello\r\n" {
		t.Fatalf("got %q, %v", line, err)
	}

	r = bufio.NewReaderSize(strings.NewReader(strings.Repeat("A", 1<<20)), 4096)
	if _, err := readLineLimited(r, maxLineLen); !errors.Is(err, bufio.ErrTooLong) {
		t.Fatalf("err = %v, want bufio.ErrTooLong", err)
	}

	// A long line that still fits spans several buffer fills.
	long := strings.Repeat("B", 3000) + "\n"
	r = bufio.NewReaderSize(strings.NewReader(long), 16)
	line, err = readLineLimited(r, maxLineLen)
	if err != nil || line != long {
		t.Fatalf("long line: len=%d err=%v", len(line), err)
	}

	r = bufio.NewReader(strings.NewReader("no newline"))
	if _, err := readLineLimited(r, 32); !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want io.EOF", err)
	}
}

func TestProxyV1LineTooLong(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		_, _ = client.Write([]byte("PROXY TCP4 " + strings.Repeat("1", 4096) + "\r\n"))
	}()
	_ = server.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := newProxyConn(server); err == nil {
		t.Fatal("expected error for oversized PROXY v1 header")
	}
}

func TestTelnetEndlessLine(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := &config.Config{
		Addrs:          map[string]string{"telnet": addr},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}
	m := metrics.New(prometheus.NewRegistry(), "test")
	tr := NewTelnet(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), m, NewLimiter(100, 10), &recordingAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = tr.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, _ = conn.Write(bytes.Repeat([]byte("A"), 1<<20))
	// The trap must close the connection instead of buffering the whole stream.
	_, err = io.Copy(io.Discard, conn)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("connection was not closed after an endless line")
	}
}

// --- Redis limits ---

func parseRedis(input string) ([]string, error) {
	return readRedisCommand(bufio.NewReaderSize(strings.NewReader(input), 4096))
}

func TestRedisRESPLimits(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"normal AUTH", "*2\r\n$4\r\nAUTH\r\n$3\r\nfoo\r\n", false},
		{"huge array count", "*2147483647\r\n", true},
		{"array just over cap", fmt.Sprintf("*%d\r\n", maxRESPArgs+1), true},
		{"huge bulk length", "*1\r\n$2000000000\r\n", true},
		{"bulk just over cap", fmt.Sprintf("*1\r\n$%d\r\n", maxRESPBulk+1), true},
		{"negative bulk", "*1\r\n$-5\r\n", true},
		{"truncated bulk", "*1\r\n$10\r\nabc", true},
		{"truncated header", "*3\r\n$3\r\nfoo\r\n", true},
		{"endless inline line", strings.Repeat("A", 1<<20), true},
		{"endless header line", "*1\r\n" + strings.Repeat("$", 1<<20), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseRedis(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestRedisBulkAtCap(t *testing.T) {
	val := strings.Repeat("x", maxRESPBulk)
	args, err := parseRedis(fmt.Sprintf("*1\r\n$%d\r\n%s\r\n", maxRESPBulk, val))
	if err != nil || len(args) != 1 || len(args[0]) != maxRESPBulk {
		t.Fatalf("args len=%d err=%v", len(args), err)
	}
}

func FuzzRedisCommand(f *testing.F) {
	f.Add([]byte("*2\r\n$4\r\nAUTH\r\n$3\r\nfoo\r\n"))
	f.Add([]byte("AUTH secret\r\n"))
	f.Add([]byte("*2147483647\r\n"))
	f.Add([]byte("*1\r\n$2000000000\r\n"))
	f.Add([]byte("*1\r\n$-1\r\n"))
	f.Add([]byte("*"))
	f.Fuzz(func(t *testing.T, data []byte) {
		args, err := readRedisCommand(bufio.NewReaderSize(bytes.NewReader(data), 4096))
		if err != nil {
			return
		}
		if len(data) > 0 && data[0] == '*' && len(args) > maxRESPArgs {
			t.Fatalf("%d args exceed cap", len(args))
		}
		for _, a := range args {
			if len(a) > maxLineLen {
				t.Fatalf("arg of %d bytes exceeds cap", len(a))
			}
		}
	})
}

// --- LDAP / BER limits ---

func TestBERReadLengthLimits(t *testing.T) {
	cases := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{"short form", []byte{0x05}, false},
		{"huge length", []byte{0x84, 0xFF, 0xFF, 0xFF, 0xFF}, true},
		{"just over cap", []byte{0x83, 0x01, 0x00, 0x01}, true},
		{"at cap", []byte{0x83, 0x01, 0x00, 0x00}, false},
		{"five length bytes", []byte{0x85, 0, 0, 0, 0, 1}, true},
		{"indefinite", []byte{0x80}, true},
		{"truncated", []byte{0x84, 0x00}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := berReadLength(bytes.NewReader(tc.input))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestBERReadElementHugeLength(t *testing.T) {
	_, _, err := berReadElement(bytes.NewReader([]byte{0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF}))
	if err == nil {
		t.Fatal("expected error for huge BER length")
	}
}

func TestBERReadTLVBadLengths(t *testing.T) {
	for _, in := range [][]byte{
		{0x30, 0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		{0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF},
		{0x30, 0x84, 0x7F, 0xFF, 0xFF, 0xFF, 0x01},
		{0x30, 0x81},
	} {
		if _, _, err := berReadTLV(in); err == nil {
			t.Errorf("berReadTLV(%x): expected error", in)
		}
	}
}

func FuzzBERReadElement(f *testing.F) {
	f.Add([]byte{0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF})
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01})
	f.Add([]byte{0x30, 0x82, 0x01})
	// Negative (8 byte) message ID.
	f.Add([]byte{0x30, 0x0A, 0x02, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, value, err := berReadElement(bytes.NewReader(data))
		if err == nil && len(value) > maxBERLen {
			t.Fatalf("value of %d bytes exceeds cap", len(value))
		}
		// Parsers working on the buffered value must never panic.
		_, _, _ = berReadTLV(data)
		id, rest, err := berReadInteger(data)
		if err == nil {
			_ = berInteger(0x02, id)
			_ = berBuildBindResponse(id, 49, "", "")
			_, _, _ = berReadOctetString(rest)
		}
	})
}

// --- Panic isolation ---

func panicCount(t *testing.T, m *metrics.Metrics, protocol string) float64 {
	t.Helper()
	var out dto.Metric
	if err := m.PanicsRecovered.WithLabelValues(protocol).Write(&out); err != nil {
		t.Fatal(err)
	}
	return out.GetCounter().GetValue()
}

func TestSafelyRecoversAndCounts(t *testing.T) {
	// Use a fresh limiter: the global one allows only a few stack logs per protocol, so repeated runs would exhaust it.
	old := panicLog
	panicLog = newPanicLimiter(time.Now)
	defer func() { panicLog = old }()

	m := metrics.New(prometheus.NewRegistry(), "test")
	buf := &syncBuffer{}
	safely(newJSONLogger(buf), m, "redis", func() { panic("boom") })

	if got := panicCount(t, m, "redis"); got != 1 {
		t.Errorf("panics counter = %v, want 1", got)
	}
	if !strings.Contains(buf.String(), "boom") || !strings.Contains(buf.String(), "stack") {
		t.Errorf("log should contain the panic value and stack: %s", buf.String())
	}

	ran := false
	safely(nil, nil, "x", func() { ran = true })
	if !ran {
		t.Error("fn should run when it does not panic")
	}
}

func TestSafelyRunsDefersBeforeRecover(t *testing.T) {
	l := NewLimiter(1, 1)
	safely(nil, nil, "x", func() {
		if !l.Acquire("192.0.2.1") {
			t.Fatal("acquire failed")
		}
		defer l.Release("192.0.2.1")
		panic("boom")
	})
	if !l.Acquire("192.0.2.1") {
		t.Fatal("limiter slot leaked after panic")
	}
}

type panicHandler struct {
	mu    sync.Mutex
	calls int
}

func (h *panicHandler) HandlePacket(_ context.Context, _ *Session, data []byte, respond func([]byte)) {
	h.mu.Lock()
	h.calls++
	h.mu.Unlock()
	if string(data) == "panic" {
		panic("malformed input")
	}
	respond([]byte("ok"))
}

func freeUDPAddr(t *testing.T) string {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := c.LocalAddr().String()
	c.Close()
	return addr
}

func TestUDPPanicDoesNotStopTrapOrLeakSlot(t *testing.T) {
	addr := freeUDPAddr(t)
	m := metrics.New(prometheus.NewRegistry(), "test")
	limiter := NewLimiter(10, 1)
	h := &panicHandler{}
	tr := NewUDP("dns", []string{addr}, slog.New(slog.NewTextHandler(io.Discard, nil)), m, limiter, newUDPRateLimiter(&config.Config{}), h)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = tr.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	// MaxPerIP is 1: a leaked slot would reject every later packet.
	for i := 0; i < 3; i++ {
		_, _ = conn.Write([]byte("panic"))
		time.Sleep(100 * time.Millisecond)
	}
	if got := panicCount(t, m, "dns"); got != 3 {
		t.Errorf("panics counter = %v, want 3", got)
	}

	_, _ = conn.Write([]byte("hello"))
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != "ok" {
		t.Fatalf("trap stopped serving after panics: n=%d err=%v", n, err)
	}
}

func TestAcceptRecoversFromMalformedProxyHeader(t *testing.T) {
	ml, err := ListenMultiTCP(context.Background(), []string{"127.0.0.1:0"}, true, nil, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer ml.Close()
	addr := ml.Addr().String()

	bad, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	_, _ = bad.Write([]byte("PROXY TCP4 garbage\r\n"))

	good, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer good.Close()
	_, _ = good.Write([]byte("PROXY TCP4 192.0.2.5 192.0.2.6 1111 2222\r\n"))

	done := make(chan net.Conn, 1)
	go func() {
		c, _ := ml.Accept()
		done <- c
	}()
	select {
	case c := <-done:
		if c == nil || !strings.HasPrefix(c.RemoteAddr().String(), "192.0.2.5") {
			t.Fatalf("unexpected conn %v", c)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("listener stopped accepting after a malformed PROXY header")
	}
}

// --- UDP: no alerts, rate limiting ---

func TestUDPTrapsNeverAlert(t *testing.T) {
	// The UDP constructors take no alerter, so a handler cannot alert. This
	// smoke test also hands the registry factories a recording alerter.
	query := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 7}
	query = append(query, "example"...)
	query = append(query, 3)
	query = append(query, "com"...)
	query = append(query, 0, 0, 1, 0, 1)

	ntpReq := make([]byte, 48)
	ntpReq[0] = (4 << 3) | 3

	pdu := berSequence(0xA0, berInteger(0x02, 1), berInteger(0x02, 0), berInteger(0x02, 0), berSequence(0x30))
	snmpReq := berSequence(0x30, berInteger(0x02, 1), berOctetString(0x04, []byte("public")), pdu)

	sipReq := []byte("OPTIONS sip:example.com SIP/2.0\r\nVia: SIP/2.0/UDP host\r\nFrom: <sip:a@example.com>\r\nTo: <sip:b@example.com>\r\nCall-ID: 1\r\n\r\n")

	cases := []struct {
		protocol string
		packet   []byte
	}{
		{"dns", query},
		{"ntp", ntpReq},
		{"snmp", snmpReq},
		{"sip", sipReq},
	}
	for _, tc := range cases {
		t.Run(tc.protocol, func(t *testing.T) {
			addr := freeUDPAddr(t)
			rec := &recordingAlerter{}
			cfg := &config.Config{Addrs: map[string]string{tc.protocol: addr}, SessionTimeout: time.Second}
			m := metrics.New(prometheus.NewRegistry(), "test")
			tr, err := Registry[tc.protocol](cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), m, NewLimiter(10, 10), rec)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() { _ = tr.Start(ctx) }()
			time.Sleep(100 * time.Millisecond)

			conn, err := net.Dial("udp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

			_, _ = conn.Write(tc.packet)
			buf := make([]byte, 512)
			if _, err := conn.Read(buf); err != nil {
				t.Fatalf("no %s response: %v", tc.protocol, err)
			}
			if got := rec.snapshot(); len(got) != 0 {
				t.Errorf("UDP trap raised alerts: %+v", got)
			}
		})
	}
}

func TestUDPRateLimiterBurstAndRefill(t *testing.T) {
	now := time.Now()
	l := newUDPRateLimiter(&config.Config{UDPRatePerSource: 10, UDPRateBurst: 20, UDPRateGlobal: 1000})
	l.nowFunc = func() time.Time { return now }
	l.globalB.last = now

	allowed := 0
	for i := 0; i < 10000; i++ {
		if l.Allow("192.0.2.1") {
			allowed++
		}
	}
	if allowed != 20 {
		t.Errorf("allowed %d packets in one instant, want burst 20", allowed)
	}

	now = now.Add(time.Second)
	allowed = 0
	for i := 0; i < 100; i++ {
		if l.Allow("192.0.2.1") {
			allowed++
		}
	}
	if allowed != 10 {
		t.Errorf("allowed %d after 1s, want refill 10", allowed)
	}

	if !l.Allow("192.0.2.2") {
		t.Error("another source must have its own bucket")
	}
}

func TestUDPRateLimiterGlobalBoundsSpoofedSources(t *testing.T) {
	now := time.Now()
	l := newUDPRateLimiter(&config.Config{UDPRatePerSource: 10, UDPRateBurst: 20, UDPRateGlobal: 100})
	l.nowFunc = func() time.Time { return now }
	l.globalB.last = now
	l.maxSources = 50

	allowed := 0
	for i := 0; i < 5000; i++ {
		if l.Allow(fmt.Sprintf("src-%d", i)) {
			allowed++
		}
	}
	if allowed != 100 {
		t.Errorf("allowed %d packets from many sources, want global burst 100", allowed)
	}
	if len(l.sources) > 50 {
		t.Errorf("per-source map has %d entries, cap is 50", len(l.sources))
	}
}

func TestUDPRateLimiterSweepsIdleSources(t *testing.T) {
	now := time.Now()
	l := newUDPRateLimiter(&config.Config{UDPRatePerSource: 10, UDPRateBurst: 20, UDPRateGlobal: 100000})
	l.nowFunc = func() time.Time { return now }
	l.globalB.last = now
	l.maxSources = 3
	for i := 0; i < 3; i++ {
		l.Allow(fmt.Sprintf("src-%d", i))
	}
	now = now.Add(10 * time.Second)
	l.Allow("fresh")
	if _, ok := l.sources["fresh"]; !ok {
		t.Error("new source should be tracked after idle ones are swept")
	}
	if len(l.sources) > 3 {
		t.Errorf("map size %d exceeds cap", len(l.sources))
	}
}

func TestUDPFloodIsBounded(t *testing.T) {
	addr := freeUDPAddr(t)
	m := metrics.New(prometheus.NewRegistry(), "test")
	h := &panicHandler{}
	cfg := &config.Config{UDPRatePerSource: 1, UDPRateBurst: 5, UDPRateGlobal: 1000}
	// A frozen clock removes refill, so the bound is exactly the burst.
	now := time.Now()
	rate := newUDPRateLimiter(cfg)
	rate.nowFunc = func() time.Time { return now }
	rate.globalB.last = now
	tr := NewUDP("dns", []string{addr}, slog.New(slog.NewTextHandler(io.Discard, nil)), m, NewLimiter(1000, 1000), rate, h)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = tr.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for i := 0; i < 300; i++ {
		_, _ = conn.Write([]byte("x"))
	}

	handled := func() int {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.calls
	}
	deadline := time.Now().Add(2 * time.Second)
	for handled() < 5 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond) // let any excess packets show up
	if calls := handled(); calls == 0 || calls > 5 {
		t.Errorf("handled %d packets of a 300 packet flood, want 1..5 (burst)", calls)
	}
	var out dto.Metric
	if err := m.UDPRateLimited.WithLabelValues("dns").Write(&out); err != nil {
		t.Fatal(err)
	}
	if got := out.GetCounter().GetValue(); got < 100 {
		t.Errorf("ran_udp_rate_limited_total = %v, want most of the flood counted", got)
	}
}

func TestUDPRateLimiterTenThousandPacketsInOneSecond(t *testing.T) {
	const perSource, burst = 20, 40
	now := time.Now()
	l := newUDPRateLimiter(&config.Config{UDPRatePerSource: perSource, UDPRateBurst: burst, UDPRateGlobal: 1000000})
	l.nowFunc = func() time.Time { return now }
	l.globalB.last = now

	allowed := 0
	for i := 0; i < 10000; i++ {
		now = now.Add(100 * time.Microsecond) // 10000 packets spread over one second
		if l.Allow("192.0.2.1") {
			allowed++
		}
	}
	if max := burst + perSource; allowed > max {
		t.Errorf("allowed %d packets, want at most burst + rate*elapsed = %d", allowed, max)
	}
	if allowed < burst {
		t.Errorf("allowed %d packets, want at least the burst %d", allowed, burst)
	}
}

func TestUDPRateLimiterSourceCapFallsBackToGlobal(t *testing.T) {
	now := time.Now()
	l := newUDPRateLimiter(&config.Config{UDPRatePerSource: 1, UDPRateBurst: 1, UDPRateGlobal: 50})
	l.nowFunc = func() time.Time { return now }
	l.globalB.last = now
	l.maxSources = 2
	l.Allow("a")
	l.Allow("b")

	// Untracked sources skip the per-source bucket and only meet the global one.
	allowed := 0
	for i := 0; i < 1000; i++ {
		if l.Allow(fmt.Sprintf("extra-%d", i)) {
			allowed++
		}
	}
	if len(l.sources) != 2 {
		t.Errorf("per-source map has %d entries, cap is 2", len(l.sources))
	}
	if allowed == 0 || allowed > 50 {
		t.Errorf("allowed %d packets from untracked sources, want 1..50 (global burst)", allowed)
	}
}

func TestNTLMSSPReadFieldOffsets(t *testing.T) {
	// Field header at offset 0: length 4, max length 4, buffer offset.
	build := func(bufOffset uint32) []byte {
		b := make([]byte, 16)
		binary.LittleEndian.PutUint16(b[0:2], 4)
		binary.LittleEndian.PutUint32(b[4:8], bufOffset)
		copy(b[8:], []byte{'a', 0, 'b', 0}) // UTF-16LE "ab"
		return b
	}
	if got := ntlmsspReadField(build(8), 0); got != "ab" {
		t.Errorf("valid offset: got %q", got)
	}
	// Offsets that are negative as a 32-bit int, or overflow offset+length.
	for _, off := range []uint32{0x7FFFFFFD, 0x80000000, 0xFFFFFFFC, 0xFFFFFFFF, 14} {
		if got := ntlmsspReadField(build(off), 0); got != "" {
			t.Errorf("offset %#x: got %q, want empty", off, got)
		}
	}
}

// --- PROXY header handling off the accept path ---

func dialProxyListener(t *testing.T, proxyProto bool) (*MultiListener, string) {
	t.Helper()
	ml, err := ListenMultiTCP(context.Background(), []string{"127.0.0.1:0"}, proxyProto, nil, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ml.Close() })
	return ml, ml.Addr().String()
}

func TestSilentPeerDoesNotBlockProxyAccept(t *testing.T) {
	ml, addr := dialProxyListener(t, true)

	silent, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	time.Sleep(50 * time.Millisecond)

	good, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer good.Close()
	_, _ = good.Write([]byte("PROXY TCP4 192.0.2.5 192.0.2.6 1111 2222\r\n"))

	done := make(chan net.Conn, 1)
	go func() {
		c, _ := ml.Accept()
		done <- c
	}()
	select {
	case c := <-done:
		if c == nil || !strings.HasPrefix(c.RemoteAddr().String(), "192.0.2.5") {
			t.Fatalf("unexpected conn %v", c)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a silent peer blocked the accept loop")
	}
}

func TestProxyListenerCloseWithPendingSilentConn(t *testing.T) {
	ml, addr := dialProxyListener(t, true)

	silent, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	time.Sleep(100 * time.Millisecond)

	closed := make(chan struct{})
	go func() {
		_ = ml.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close hung with a connection still waiting for its header")
	}

	// The pending connection is closed by the listener.
	_ = silent.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := silent.Read(make([]byte, 1)); err == nil {
		t.Error("expected the pending connection to be closed")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Error("pending connection was left open after Close")
	}
}

func TestParseV1Validation(t *testing.T) {
	cases := []struct {
		line    string
		wantErr bool
	}{
		{"PROXY TCP4 192.0.2.1 192.0.2.2 1234 80\r\n", false},
		{"PROXY TCP4 192.0.2.1 192.0.2.2 0 80\r\n", false},
		{"PROXY TCP4 192.0.2.1 192.0.2.2 65535 80\r\n", false},
		{"PROXY TCP6 2001:db8::1 2001:db8::2 1234 80\r\n", false},
		{"PROXY TCP4 192.0.2.1 192.0.2.2 -5 80\r\n", true},
		{"PROXY TCP4 192.0.2.1 192.0.2.2 65536 80\r\n", true},
		{"PROXY TCP4 192.0.2.1 192.0.2.2 +5 80\r\n", true},
		{"PROXY TCP4 192.0.2.1 192.0.2.2 abc 80\r\n", true},
		{"PROXY TCP4 a 192.0.2.2 5 80\r\n", true},
		{"PROXY TCP4 not-an-ip 192.0.2.2 5 80\r\n", true},
		{"PROXY TCP4 999.1.1.1 192.0.2.2 5 80\r\n", true},
		{"PROXY TCP6 fe80::1%eth0 2001:db8::2 5 80\r\n", true},
		{"PROXY TCP4 192.0.2.1:5 192.0.2.2 5 80\r\n", true},
	}
	for _, tc := range cases {
		_, err := parseV1(bufio.NewReader(strings.NewReader(tc.line)))
		if (err != nil) != tc.wantErr {
			t.Errorf("%q: err = %v, wantErr %v", tc.line, err, tc.wantErr)
		}
	}
}

// --- Panic log rate limiting ---

func TestPanicLimiterSamplesLogs(t *testing.T) {
	now := time.Now()
	p := newPanicLimiter(func() time.Time { return now })

	for i := 0; i < panicStackLimit; i++ {
		if logIt, withStack, _ := p.allow("redis"); !logIt || !withStack {
			t.Fatalf("panic %d: want logged with stack", i+1)
		}
	}
	for i := 0; i < 100; i++ {
		if logIt, _, _ := p.allow("redis"); logIt {
			t.Fatal("panic inside the sampling interval was logged")
		}
	}
	// Another protocol has its own budget.
	if logIt, withStack, _ := p.allow("ldap"); !logIt || !withStack {
		t.Error("per-protocol budget expected")
	}

	now = now.Add(panicLogInterval)
	logIt, withStack, suppressed := p.allow("redis")
	if !logIt || withStack || suppressed != 100 {
		t.Errorf("sampled log = %v stack=%v suppressed=%d, want true false 100", logIt, withStack, suppressed)
	}
	if logIt, _, _ := p.allow("redis"); logIt {
		t.Error("only one sampled log per interval")
	}
}

func TestSafelyAlwaysCountsButLimitsLogs(t *testing.T) {
	now := time.Now()
	old := panicLog
	panicLog = newPanicLimiter(func() time.Time { return now })
	defer func() { panicLog = old }()

	m := metrics.New(prometheus.NewRegistry(), "test")
	buf := &syncBuffer{}
	logger := newJSONLogger(buf)
	for i := 0; i < 50; i++ {
		safely(logger, m, "redis", func() { panic("boom") })
	}
	if got := panicCount(t, m, "redis"); got != 50 {
		t.Errorf("panics counter = %v, want 50", got)
	}
	if lines := strings.Count(buf.String(), "panic recovered"); lines != panicStackLimit {
		t.Errorf("%d panic logs, want %d", lines, panicStackLimit)
	}

	now = now.Add(2 * time.Second)
	safely(logger, m, "redis", func() { panic("boom") })
	if lines := strings.Count(buf.String(), "panic recovered"); lines != panicStackLimit+1 {
		t.Errorf("%d panic logs after the interval, want %d", lines, panicStackLimit+1)
	}
}

func TestRecoverHandlerCountsHTTPPanics(t *testing.T) {
	// Fresh limiter: the global one suppresses logs after a few panics per protocol, so repeated runs would miss the line.
	old := panicLog
	panicLog = newPanicLimiter(time.Now)
	defer func() { panicLog = old }()

	m := metrics.New(prometheus.NewRegistry(), "test")
	buf := &syncBuffer{}
	h := recoverHandler(newJSONLogger(buf), m, "http", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("handler boom")
	}))
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected the connection to be aborted")
	}
	// The handler goroutine may still be logging after the client saw the abort.
	waitFor(t, func() bool { return strings.Contains(buf.String(), "handler boom") })
	if got := panicCount(t, m, "http"); got != 1 {
		t.Errorf("panics counter = %v, want 1", got)
	}
	if n := strings.Count(buf.String(), "handler boom"); n != 1 {
		t.Errorf("panic logged %d times, want once", n)
	}

	// The server keeps serving afterwards.
	ok := httptest.NewServer(recoverHandler(nil, m, "http", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})))
	defer ok.Close()
	resp, err = http.Get(ok.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}
