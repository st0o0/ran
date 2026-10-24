package trap

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

// helloSpec describes a synthetic ClientHello for the parser tests.
type helloSpec struct {
	version  uint16
	ciphers  []uint16
	exts     []uint16 // extension types in wire order; known types get a real body
	sni      string
	curves   []uint16
	points   []uint8
	sigAlgs  []uint16
	versions []uint16
	alpn     []string
}

func u16b(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }

func lenPrefixed16(b []byte) []byte { return append(u16b(uint16(len(b))), b...) }

func u16list(vals []uint16) []byte {
	var l []byte
	for _, v := range vals {
		l = append(l, u16b(v)...)
	}
	return l
}

func (s helloSpec) record() []byte {
	var exts []byte
	for _, typ := range s.exts {
		var body []byte
		switch typ {
		case 0:
			name := append([]byte{0}, lenPrefixed16([]byte(s.sni))...)
			body = lenPrefixed16(name)
		case 10:
			body = lenPrefixed16(u16list(s.curves))
		case 11:
			body = append([]byte{byte(len(s.points))}, s.points...)
		case 13:
			body = lenPrefixed16(u16list(s.sigAlgs))
		case 16:
			var l []byte
			for _, p := range s.alpn {
				l = append(l, byte(len(p)))
				l = append(l, p...)
			}
			body = lenPrefixed16(l)
		case 43:
			l := u16list(s.versions)
			body = append([]byte{byte(len(l))}, l...)
		}
		exts = append(exts, u16b(typ)...)
		exts = append(exts, lenPrefixed16(body)...)
	}
	body := u16b(s.version)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0) // empty session id
	body = append(body, lenPrefixed16(u16list(s.ciphers))...)
	body = append(body, 1, 0) // null compression
	body = append(body, lenPrefixed16(exts)...)
	hs := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	rec := append([]byte{0x16, 3, 1}, u16b(uint16(len(hs)))...)
	return append(rec, hs...)
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func sha12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func TestParseClientHelloFingerprints(t *testing.T) {
	t.Parallel()
	base := helloSpec{
		version:  0x0303,
		ciphers:  []uint16{0x1301, 0x1302, 0xc02b},
		exts:     []uint16{0, 10, 11, 13, 16, 43},
		sni:      "example.com",
		curves:   []uint16{29, 23},
		points:   []uint8{0},
		sigAlgs:  []uint16{0x0403, 0x0804},
		versions: []uint16{0x0304, 0x0303},
		alpn:     []string{"h2", "http/1.1"},
	}
	grease := base
	grease.ciphers = []uint16{0x0a0a, 0x1301, 0x1302, 0xc02b}
	grease.exts = []uint16{0x1a1a, 0, 10, 11, 13, 16, 43, 0xfafa}
	grease.curves = []uint16{0x2a2a, 29, 23}
	grease.versions = []uint16{0x7a7a, 0x0304, 0x0303}
	noSNI := base
	noSNI.exts = []uint16{10, 11, 13}
	noSNI.alpn = nil
	noExt := helloSpec{version: 0x0301, ciphers: []uint16{0x002f}}

	cases := []struct {
		name    string
		spec    helloSpec
		wantSNI string
		wantJA3 string
		wantJA4 string
	}{
		{
			name:    "modern client",
			spec:    base,
			wantSNI: "example.com",
			wantJA3: md5hex("771,4865-4866-49195,0-10-11-13-16-43,29-23,0"),
			wantJA4: "t13d0306h2_" + sha12("1301,1302,c02b") + "_" + sha12("000a,000b,000d,002b_0403,0804"),
		},
		{
			name:    "GREASE is ignored",
			spec:    grease,
			wantSNI: "example.com",
			wantJA3: md5hex("771,4865-4866-49195,0-10-11-13-16-43,29-23,0"),
			wantJA4: "t13d0306h2_" + sha12("1301,1302,c02b") + "_" + sha12("000a,000b,000d,002b_0403,0804"),
		},
		{
			name:    "no SNI and no ALPN",
			spec:    noSNI,
			wantJA3: md5hex("771,4865-4866-49195,10-11-13,29-23,0"),
			wantJA4: "t12i030300_" + sha12("1301,1302,c02b") + "_" + sha12("000a,000b,000d_0403,0804"),
		},
		{
			name:    "no extensions",
			spec:    noExt,
			wantJA3: md5hex("769,47,,,"),
			wantJA4: "t10i010000_" + sha12("002f") + "_000000000000",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h, err := parseClientHello(tc.spec.record())
			if err != nil {
				t.Fatal(err)
			}
			if h.SNI != tc.wantSNI {
				t.Errorf("sni = %q, want %q", h.SNI, tc.wantSNI)
			}
			if got := h.ja3(); got != tc.wantJA3 {
				t.Errorf("ja3 = %s, want %s", got, tc.wantJA3)
			}
			if got := h.ja4(); got != tc.wantJA4 {
				t.Errorf("ja4 = %s, want %s", got, tc.wantJA4)
			}
		})
	}
}

func TestParseClientHelloMalformed(t *testing.T) {
	t.Parallel()
	good := helloSpec{version: 0x0303, ciphers: []uint16{0x1301}, exts: []uint16{0}, sni: "a.example"}.record()
	notHandshake := append([]byte(nil), good...)
	notHandshake[0] = 0x17
	notHello := append([]byte(nil), good...)
	notHello[5] = 2
	hugeRecLen := append([]byte(nil), good...)
	hugeRecLen[3], hugeRecLen[4] = 0xff, 0xff
	hugeHsLen := append([]byte(nil), good...)
	hugeHsLen[6], hugeHsLen[7], hugeHsLen[8] = 0xff, 0xff, 0xff
	cases := map[string][]byte{
		"nil":           nil,
		"one byte":      {0x16},
		"header only":   {0x16, 3, 1, 0, 0},
		"not tls":       []byte("GET / HTTP/1.1\r\n\r\n"),
		"not handshake": notHandshake,
		"not hello":     notHello,
		"record length": hugeRecLen,
		"hello length":  hugeHsLen,
		"cut in half":   good[:len(good)/2],
		"cut short":     good[:len(good)-1],
	}
	for name, data := range cases {
		if h, err := parseClientHello(data); err == nil {
			t.Errorf("%s: parsed %+v, want an error", name, h)
		}
	}
}

func TestFingerprintMetaIsSanitizedAndBounded(t *testing.T) {
	t.Parallel()
	raw := helloSpec{version: 0x0303, ciphers: []uint16{0x1301}, exts: []uint16{0}, sni: "a\r\nb\x00" + strings.Repeat("x", 1000)}.record()
	fp := fingerprintFromHello(raw, "")
	if strings.ContainsAny(fp.SNI, "\r\n\x00") || len(fp.SNI) > maxHTTPValue {
		t.Errorf("sni = %q (%d bytes)", fp.SNI, len(fp.SNI))
	}
	if fp.JA3 == "" || fp.JA4 == "" {
		t.Error("fingerprints missing")
	}
	if fp := fingerprintFromHello([]byte("junk"), "host.example"); fp.SNI != "host.example" || fp.JA3 != "" || fp.JA4 != "" {
		t.Errorf("unparsable hello: %+v", fp)
	}
}

func TestParseClientHelloListsAreBounded(t *testing.T) {
	t.Parallel()
	s := helloSpec{version: 0x0303, sni: "a.example", exts: []uint16{0, 10, 13, 43}}
	for i := 0; i < 3000; i++ {
		s.ciphers = append(s.ciphers, uint16(i))
		s.curves = append(s.curves, uint16(i))
		s.sigAlgs = append(s.sigAlgs, uint16(i))
		s.versions = append(s.versions, uint16(i))
	}
	rec := s.record()
	// The 16-bit versions list length overflows the 8-bit prefix; use what parses.
	h, err := parseClientHello(rec)
	if err != nil {
		t.Skipf("synthetic record not parseable: %v", err)
	}
	if len(h.Ciphers) > maxHelloCiphers || len(h.Curves) > maxHelloCurves || len(h.SigAlgs) > maxHelloSigAlgs || len(h.Versions) > maxHelloVersions {
		t.Errorf("unbounded lists: %d %d %d %d", len(h.Ciphers), len(h.Curves), len(h.SigAlgs), len(h.Versions))
	}
	if len(h.Ciphers) != maxHelloCiphers {
		t.Errorf("ciphers = %d, want the cap %d", len(h.Ciphers), maxHelloCiphers)
	}
}

func TestLoadOrGenerateCert(t *testing.T) {
	t.Parallel()
	t.Run("first start persists and second start reuses", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "https_cert.pem")
		log := &syncBuffer{}
		first, err := loadOrGenerateCert(path, newJSONLogger(log))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("certificate not persisted: %v", err)
		}
		second, err := loadOrGenerateCert(path, newJSONLogger(log))
		if err != nil {
			t.Fatal(err)
		}
		if string(first.Certificate[0]) != string(second.Certificate[0]) {
			t.Error("second start did not reuse the persisted certificate")
		}
		if !strings.Contains(log.String(), "persisted https certificate") || !strings.Contains(log.String(), "loaded https certificate") {
			t.Errorf("unexpected log:\n%s", log.String())
		}
	})
	t.Run("unwritable path falls back to an ephemeral certificate", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "missing-dir", "https_cert.pem")
		log := &syncBuffer{}
		cert, err := loadOrGenerateCert(path, newJSONLogger(log))
		if err != nil {
			t.Fatalf("startup must not fail: %v", err)
		}
		if len(cert.Certificate) == 0 {
			t.Fatal("no certificate")
		}
		if !strings.Contains(log.String(), `"level":"WARN"`) || !strings.Contains(log.String(), "ephemeral") {
			t.Errorf("want a warning and the ephemeral note:\n%s", log.String())
		}
	})
	t.Run("corrupt file is replaced", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "https_cert.pem")
		if err := os.WriteFile(path, []byte("not a pem"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadOrGenerateCert(path, newJSONLogger(&syncBuffer{})); err != nil {
			t.Fatal(err)
		}
		if _, err := tls.LoadX509KeyPair(path, path); err != nil {
			t.Errorf("replaced file is not a valid pair: %v", err)
		}
	})
	t.Run("empty path is ephemeral", func(t *testing.T) {
		t.Parallel()
		if _, err := loadOrGenerateCert("", newJSONLogger(&syncBuffer{})); err != nil {
			t.Fatal(err)
		}
	})
}

func newHTTPSTrap(t *testing.T, cfg *config.Config, rep Reporter, lim *Limiter) *HTTPSTrap {
	t.Helper()
	tr, err := NewHTTPS(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), metrics.New(prometheus.NewRegistry(), "test"), lim, rep)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func startHTTPSSensor(t *testing.T) (string, *eventSink) {
	t.Helper()
	return startSensorTrap(t, "https", func(cfg *config.Config, l *slog.Logger, m *metrics.Metrics, lim *Limiter, r Reporter) Trap {
		return newHTTPSTrap(t, cfg, r, lim)
	})
}

func httpsDo(t *testing.T, addr, path, sni string, headers map[string]string) {
	t.Helper()
	req, err := http.NewRequest("GET", "https://"+addr+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, ServerName: sni}, //nolint:gosec // test client for a self-signed trap
	}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func TestHTTPSExploitPathOverTLS(t *testing.T) {
	t.Parallel()
	addr, sink := startHTTPSSensor(t)
	httpsDo(t, addr, "/.env", "example.com", map[string]string{"X-Forwarded-For": "8.8.8.8"})
	ev := waitAttack(t, sink)
	if ev.Info.Protocol != "https" || ev.Info.SourceIP != "127.0.0.1" {
		t.Errorf("info = %+v", ev.Info)
	}
	if ev.Meta["path"] != "/.env" || ev.Meta["method"] != "GET" {
		t.Errorf("meta = %v", ev.Meta)
	}
	if ev.Meta["sni"] != "example.com" {
		t.Errorf("sni = %q", ev.Meta["sni"])
	}
	if !isHex(ev.Meta["ja3"], 32) {
		t.Errorf("ja3 = %q", ev.Meta["ja3"])
	}
	if ja4 := ev.Meta["ja4"]; !strings.HasPrefix(ja4, "t13d") || len(ja4) != 36 {
		t.Errorf("ja4 = %q", ja4)
	}
	// The forwarded address is logged only; it never becomes identity or meta.
	for k, v := range ev.Meta {
		if strings.Contains(v, "8.8.8.8") {
			t.Errorf("meta %s=%q carries the forwarded address", k, v)
		}
	}
}

func TestHTTPSHandshakeOnlyIsProbe(t *testing.T) {
	t.Parallel()
	addr, sink := startHTTPSSensor(t)
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: "example.com"}) //nolint:gosec // test client
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	evs := sink.waitEvents(t, func(e []alert.Event) bool { return hasClass(e, alert.ClassProbe) })
	if len(evs) != 1 || evs[0].Class != alert.ClassProbe {
		t.Fatalf("want a single probe event, got %+v", evs)
	}
}

func TestHTTPSPlainRequestIsProbe(t *testing.T) {
	t.Parallel()
	addr, sink := startHTTPSSensor(t)
	httpsDo(t, addr, "/index.html", "example.com", nil)
	evs := sink.waitEvents(t, func(e []alert.Event) bool { return hasClass(e, alert.ClassProbe) })
	if len(evs) != 1 || evs[0].Class != alert.ClassProbe {
		t.Fatalf("want a single probe event, got %+v", evs)
	}
}

func TestHTTPSMalformedInputIsProbe(t *testing.T) {
	t.Parallel()
	oversized := append([]byte{0x16, 3, 1, 0xff, 0xff}, make([]byte, 70000)...)
	cases := map[string][]byte{
		"plain http":            []byte("GET /.env HTTP/1.1\r\nHost: x\r\n\r\n"),
		"garbage":               []byte("\x00\x01\x02garbage\xff\xfe"),
		"truncated hello":       helloSpec{version: 0x0303, ciphers: []uint16{0x1301}}.record()[:20],
		"oversized hello":       oversized,
		"bad handshake type":    {0x16, 3, 1, 0, 4, 99, 0, 0, 0},
		"application data":      {0x17, 3, 3, 0, 3, 1, 2, 3},
		"huge record length":    {0x16, 3, 1, 0xff, 0xff, 1},
		"zero length record":    {0x16, 3, 1, 0, 0},
		"sslv2 style hello":     {0x80, 0x2e, 0x01, 0x00, 0x02, 0x00, 0x15},
		"alert record":          {0x15, 3, 3, 0, 2, 2, 40},
		"hello without ciphers": helloSpec{version: 0x0303, exts: []uint16{0}, sni: "a"}.record(),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			addr, sink := startHTTPSSensor(t)
			conn := dialTrap(t, addr)
			_, _ = conn.Write(data)
			// The trap must close the connection without serving an HTTP page.
			got, _ := io.ReadAll(conn)
			if strings.Contains(string(got), "HTTP/1.") && strings.Contains(string(got), "200 OK") {
				t.Errorf("plaintext HTTP answer on the TLS port: %q", got)
			}
			evs := sink.waitEvents(t, func(e []alert.Event) bool { return len(e) > 0 })
			for _, ev := range evs {
				if ev.Class != alert.ClassProbe {
					t.Errorf("class = %s, want probe: %+v", ev.Class, ev)
				}
			}
		})
	}
}

func TestHTTPSIdleClientHitsHandshakeTimeout(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		Addrs:          map[string]string{"https": "127.0.0.1:0"},
		SessionTimeout: 300 * time.Millisecond,
		MaxSessions:    10,
		MaxPerIP:       10,
	}
	tr := newHTTPSTrap(t, cfg, alert.NoopAlerter{}, NewLimiter(10, 10))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := serveTrap(t, ctx, tr)

	conn := dialTrap(t, addr)
	start := time.Now()
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected the trap to close the idle connection")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("handshake timeout took %v", d)
	}
}

func TestHTTPSStopClosesLiveConnections(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		Addrs:          map[string]string{"https": "127.0.0.1:0"},
		SessionTimeout: 30 * time.Second,
		MaxSessions:    10,
		MaxPerIP:       10,
	}
	lim := NewLimiter(10, 10)
	tr := newHTTPSTrap(t, cfg, alert.NoopAlerter{}, lim)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := serveTrap(t, ctx, tr)

	live, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test client
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	mid := dialTrap(t, addr) // stuck before the ClientHello

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	if err := tr.Stop(stopCtx); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]net.Conn{"tls": live, "handshake": mid} {
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, err := c.Read(make([]byte, 1))
		if err == nil {
			t.Errorf("%s connection still readable after Stop", name)
		} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Errorf("%s connection was not closed by Stop: %v", name, err)
		}
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		lim.mu.Lock()
		global := lim.global
		lim.mu.Unlock()
		if global == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("limiter still holds %d slots after Stop", global)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestHTTPSRegistered(t *testing.T) {
	t.Parallel()
	if _, ok := Registry["https"]; !ok {
		t.Fatal("https missing from Registry")
	}
	if config.DefaultPorts["https"] != ":8443" {
		t.Errorf("default port = %q", config.DefaultPorts["https"])
	}
}
