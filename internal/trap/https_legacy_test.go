package trap

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

// --- certificates ---

func TestLoadOrGenerateCerts(t *testing.T) {
	t.Parallel()
	t.Run("first start persists and second start reuses", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "https_cert.pem")
		log := &syncBuffer{}
		first, err := loadOrGenerateCerts(path, newJSONLogger(log))
		if err != nil {
			t.Fatal(err)
		}
		if len(first) != 2 {
			t.Fatalf("got %d certificates, want ECDSA and RSA", len(first))
		}
		if _, ok := first[0].PrivateKey.(*ecdsa.PrivateKey); !ok {
			t.Errorf("first key is %T, want ECDSA", first[0].PrivateKey)
		}
		if k, ok := first[1].PrivateKey.(*rsa.PrivateKey); !ok || k.N.BitLen() != 2048 {
			t.Errorf("second key is %T, want RSA-2048", first[1].PrivateKey)
		}
		if runtime.GOOS != "windows" {
			if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
				t.Errorf("persisted file: %v, %v", fi, err)
			}
		}
		second, err := loadOrGenerateCerts(path, newJSONLogger(log))
		if err != nil {
			t.Fatal(err)
		}
		for i := range first {
			if string(first[i].Certificate[0]) != string(second[i].Certificate[0]) {
				t.Errorf("certificate %d: second start did not reuse the persisted one", i)
			}
		}
		if !strings.Contains(log.String(), "persisted https certificate") || !strings.Contains(log.String(), "loaded https certificate") {
			t.Errorf("unexpected log:\n%s", log.String())
		}
	})
	t.Run("missing directory falls back to an ephemeral certificate", func(t *testing.T) {
		t.Parallel()
		assertEphemeral(t, filepath.Join(t.TempDir(), "missing-dir", "https_cert.pem"))
	})
	t.Run("parent is a regular file", func(t *testing.T) {
		t.Parallel()
		file := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		assertEphemeral(t, filepath.Join(file, "https_cert.pem"))
	})
	t.Run("read-only directory", func(t *testing.T) {
		t.Parallel()
		if runtime.GOOS == "windows" {
			t.Skip("directory permissions are not enforced the same way on Windows")
		}
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		if f, err := os.CreateTemp(dir, "probe"); err == nil {
			f.Close()
			t.Skip("directory is writable anyway (running as root?)")
		}
		assertEphemeral(t, filepath.Join(dir, "https_cert.pem"))
	})
	t.Run("corrupt file is replaced", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "https_cert.pem")
		if err := os.WriteFile(path, []byte("not a pem"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadOrGenerateCerts(path, newJSONLogger(&syncBuffer{})); err != nil {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(path)
		if _, err := parseCertPairs(data, time.Now()); err != nil {
			t.Errorf("replaced file is not valid: %v", err)
		}
	})
	t.Run("empty path is ephemeral", func(t *testing.T) {
		t.Parallel()
		if _, err := loadOrGenerateCerts("", newJSONLogger(&syncBuffer{})); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("existing 0644 file ends up 0600 and no temp file remains", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "https_cert.pem")
		if err := os.WriteFile(path, []byte("junk"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := loadOrGenerateCerts(path, newJSONLogger(&syncBuffer{})); err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" {
			fi, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != 0o600 {
				t.Errorf("mode = %v, want 0600", fi.Mode().Perm())
			}
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 1 {
			t.Errorf("directory has %d entries, want only the certificate file", len(entries))
		}
	})
	for name, validity := range map[string][2]time.Duration{
		"expired":   {-48 * time.Hour, -24 * time.Hour},
		"not yet":   {24 * time.Hour, 48 * time.Hour},
		"one valid": {-time.Hour, time.Hour}, // control: valid files are kept
	} {
		t.Run("validity "+name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "https_cert.pem")
			now := time.Now()
			old, pemData, err := generateCerts(now.Add(validity[0]), now.Add(validity[1]))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, pemData, 0o600); err != nil {
				t.Fatal(err)
			}
			log := &syncBuffer{}
			got, err := loadOrGenerateCerts(path, newJSONLogger(log))
			if err != nil {
				t.Fatal(err)
			}
			kept := string(got[0].Certificate[0]) == string(old[0].Certificate[0])
			if wantKept := name == "one valid"; kept != wantKept {
				t.Errorf("kept = %v, want %v\n%s", kept, wantKept, log.String())
			}
			if !kept && !strings.Contains(log.String(), "unusable") {
				t.Errorf("no warning logged:\n%s", log.String())
			}
		})
	}
	t.Run("ECDSA-only file is replaced", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "https_cert.pem")
		now := time.Now()
		_, pemData, err := generateCerts(now.Add(-time.Hour), now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		// Keep only the first certificate and key (the ECDSA pair).
		half := bytes.Index(pemData, []byte("-----END PRIVATE KEY-----")) + len("-----END PRIVATE KEY-----\n")
		if err := os.WriteFile(path, pemData[:half], 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := loadOrGenerateCerts(path, newJSONLogger(&syncBuffer{}))
		if err != nil || len(got) != 2 {
			t.Fatalf("certs = %d, err = %v", len(got), err)
		}
		data, _ := os.ReadFile(path)
		if _, err := parseCertPairs(data, time.Now()); err != nil {
			t.Errorf("file not rewritten with both pairs: %v", err)
		}
	})
}

func assertEphemeral(t *testing.T, path string) {
	t.Helper()
	log := &syncBuffer{}
	certs, err := loadOrGenerateCerts(path, newJSONLogger(log))
	if err != nil {
		t.Fatalf("startup must not fail: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("got %d certificates", len(certs))
	}
	if !strings.Contains(log.String(), `"level":"WARN"`) || !strings.Contains(log.String(), "ephemeral") {
		t.Errorf("want a warning and the ephemeral note:\n%s", log.String())
	}
}

// --- handshakes with real clients ---

func TestHTTPSAcceptsOldAndRSAOnlyClients(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		min, max   uint16
		suites     []uint16
		wantKey    string
		wantSuite  uint16
		wantTLSVer uint16
	}{
		{"TLS1.2 ECDSA", tls.VersionTLS12, tls.VersionTLS12, []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}, "ecdsa", tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.VersionTLS12},
		{"TLS1.2 ECDHE RSA", tls.VersionTLS12, tls.VersionTLS12, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}, "rsa", tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.VersionTLS12},
		{"TLS1.2 RSA key exchange GCM", tls.VersionTLS12, tls.VersionTLS12, []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256}, "rsa", tls.TLS_RSA_WITH_AES_128_GCM_SHA256, tls.VersionTLS12},
		{"TLS1.2 RSA key exchange CBC", tls.VersionTLS12, tls.VersionTLS12, []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}, "rsa", tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.VersionTLS12},
		{"TLS1.2 3DES", tls.VersionTLS12, tls.VersionTLS12, []uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA}, "rsa", tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, tls.VersionTLS12},
		{"TLS1.1 RSA", tls.VersionTLS11, tls.VersionTLS11, []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}, "rsa", tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.VersionTLS11},
		{"TLS1.1 ECDSA", tls.VersionTLS11, tls.VersionTLS11, []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}, "ecdsa", tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, tls.VersionTLS11},
		{"TLS1.0 RSA", tls.VersionTLS10, tls.VersionTLS10, []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}, "rsa", tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.VersionTLS10},
		{"TLS1.0 ECDHE RSA", tls.VersionTLS10, tls.VersionTLS10, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}, "rsa", tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.VersionTLS10},
		{"TLS1.0 3DES", tls.VersionTLS10, tls.VersionTLS10, []uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA}, "rsa", tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, tls.VersionTLS10},
		{"TLS1.3", tls.VersionTLS13, tls.VersionTLS13, nil, "ecdsa", 0, tls.VersionTLS13},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			addr, sink := startHTTPSSensor(t)
			client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
				DisableKeepAlives: true,
				TLSClientConfig: &tls.Config{ //nolint:gosec // test client for a self-signed trap offering old versions
					InsecureSkipVerify: true,
					MinVersion:         tc.min,
					MaxVersion:         tc.max,
					CipherSuites:       tc.suites,
				},
			}}
			resp, err := client.Get("https://" + addr + "/.env")
			if err != nil {
				t.Fatalf("handshake or request failed: %v", err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.TLS.Version != tc.wantTLSVer {
				t.Errorf("version = %#x, want %#x", resp.TLS.Version, tc.wantTLSVer)
			}
			if tc.wantSuite != 0 && resp.TLS.CipherSuite != tc.wantSuite {
				t.Errorf("suite = %#x, want %#x", resp.TLS.CipherSuite, tc.wantSuite)
			}
			var gotKey string
			switch resp.TLS.PeerCertificates[0].PublicKey.(type) {
			case *ecdsa.PublicKey:
				gotKey = "ecdsa"
			case *rsa.PublicKey:
				gotKey = "rsa"
			}
			if gotKey != tc.wantKey {
				t.Errorf("certificate key = %s, want %s", gotKey, tc.wantKey)
			}
			ev := waitAttack(t, sink)
			if ev.Info.Protocol != "https" || ev.Meta["path"] != "/.env" {
				t.Errorf("request not recorded: %+v", ev)
			}
			if !isHex(ev.Meta["ja3"], 32) || ev.Meta["ja4"] == "" {
				t.Errorf("fingerprint missing: %v", ev.Meta)
			}
		})
	}
}

// --- logging ---

func startLoggedHTTPS(t *testing.T) (string, *syncBuffer) {
	t.Helper()
	buf := &syncBuffer{}
	cfg := &config.Config{
		Addrs:          map[string]string{"https": "127.0.0.1:0"},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    10,
		MaxPerIP:       10,
	}
	tr, err := NewHTTPS(cfg, newJSONLogger(buf), metrics.New(prometheus.NewRegistry(), "test"), NewLimiter(10, 10), alert.NoopAlerter{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	return serveTrap(t, ctx, tr), buf
}

// helloLogLine waits for the "tls client hello" log line and returns it decoded.
func helloLogLine(t *testing.T, buf *syncBuffer) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, line := range strings.Split(buf.String(), "\n") {
			if !strings.Contains(line, "tls client hello") {
				continue
			}
			var m map[string]any
			if err := json.Unmarshal([]byte(line), &m); err != nil {
				t.Fatalf("bad log line %q: %v", line, err)
			}
			return m
		}
		if time.Now().After(deadline) {
			t.Fatalf("no tls client hello log line:\n%s", buf.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestHTTPSLogsClientHello(t *testing.T) {
	t.Parallel()
	addr, buf := startLoggedHTTPS(t)
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: "example.com", NextProtos: []string{"h2", "http/1.1"}}) //nolint:gosec // test client
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	m := helloLogLine(t, buf)
	if m["sni"] != "example.com" || m["alpn"] != "h2,http/1.1" {
		t.Errorf("log line = %v", m)
	}
	if s, _ := m["ja3"].(string); !isHex(s, 32) {
		t.Errorf("ja3 = %v", m["ja3"])
	}
	if s, _ := m["ja4"].(string); !strings.HasPrefix(s, "t13d") {
		t.Errorf("ja4 = %v", m["ja4"])
	}
}

func TestHTTPSFailedHandshakeStillLogsFingerprint(t *testing.T) {
	t.Parallel()
	addr, buf := startLoggedHTTPS(t)
	// 0x1234 is not a cipher suite the server knows, so the handshake must fail.
	rec := helloSpec{version: 0x0303, ciphers: []uint16{0x1234}, exts: []uint16{0, 13}, sni: "scan.example", sigAlgs: []uint16{0x0403}}.record()
	conn := dialTrap(t, addr)
	_, _ = conn.Write(rec)
	got, _ := io.ReadAll(conn)
	if len(got) == 0 || got[0] != 0x15 {
		t.Errorf("want a TLS alert from the server, got %x", got)
	}
	m := helloLogLine(t, buf)
	if m["sni"] != "scan.example" {
		t.Errorf("sni = %v", m["sni"])
	}
	if s, _ := m["ja3"].(string); !isHex(s, 32) {
		t.Errorf("ja3 = %v", m["ja3"])
	}
	if s, _ := m["ja4"].(string); !strings.HasPrefix(s, "t12d0102") {
		t.Errorf("ja4 = %v", m["ja4"])
	}
}

func TestHTTPSFragmentedClientHelloKeepsSNIOnly(t *testing.T) {
	t.Parallel()
	addr, buf := startLoggedHTTPS(t)
	rec := helloSpec{version: 0x0303, ciphers: []uint16{0xc02f}, exts: []uint16{0, 13}, sni: "frag.example", sigAlgs: []uint16{0x0403}}.record()
	hs := rec[5:]
	const cut = 20
	var wire []byte
	for _, part := range [][]byte{hs[:cut], hs[cut:]} {
		wire = append(wire, 0x16, 3, 1)
		wire = append(wire, u16b(uint16(len(part)))...)
		wire = append(wire, part...)
	}
	conn := dialTrap(t, addr)
	_, _ = conn.Write(wire)
	m := helloLogLine(t, buf)
	if m["sni"] != "frag.example" {
		t.Errorf("sni = %v, want it from the reassembled hello", m["sni"])
	}
	if _, ok := m["ja3"]; ok {
		t.Errorf("ja3 present for a fragmented hello: %v", m)
	}
	if _, ok := m["ja4"]; ok {
		t.Errorf("ja4 present for a fragmented hello: %v", m)
	}
}

func TestPlainHTTPKeepsDefaultErrorLog(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{Addrs: map[string]string{"http": "127.0.0.1:0"}, SessionTimeout: time.Second, MaxSessions: 1, MaxPerIP: 1}
	tr := NewHTTP(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), metrics.New(prometheus.NewRegistry(), "test"), NewLimiter(1, 1), alert.NoopAlerter{})
	if tr.srv.ErrorLog != nil {
		t.Error("the plain http trap must not override the http.Server ErrorLog")
	}
	cfg.Addrs = map[string]string{"https": "127.0.0.1:0"}
	if s := newHTTPSTrap(t, cfg, alert.NoopAlerter{}, NewLimiter(1, 1)); s.srv.ErrorLog == nil {
		t.Error("the https trap discards handshake errors through ErrorLog")
	}
}

// --- fingerprint vectors ---

func TestJA3SalesforceVector(t *testing.T) {
	t.Parallel()
	// README of github.com/salesforce/ja3: the JA3 string
	// "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"
	// hashes to ada70206e40642a3e4461f35503241d5.
	h, err := parseClientHello(helloSpec{
		version: 769,
		ciphers: []uint16{47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4},
		exts:    []uint16{0, 10, 11},
		sni:     "example.com",
		curves:  []uint16{23, 24, 25},
		points:  []uint8{0},
	}.record())
	if err != nil {
		t.Fatal(err)
	}
	if got := h.ja3(); got != "ada70206e40642a3e4461f35503241d5" {
		t.Errorf("ja3 = %s", got)
	}
}

func TestJA4FoxIOCaptures(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, hex, sni, ja4 string
	}{
		{"tls12.pcap", vectorFoxIOTLS12, "contile.services.mozilla.com", "t13d1715h2_5b57614c22b0_3d5424432f57"},
		// The published value is t13d151699_...: see tlsfp_vectors_test.go.
		{"tls-non-ascii-alpn.pcapng", vectorFoxIONonASCIIALPN, "clientservices.googleapis.com", "t13d1516bd_8daaf6152771_e5627efa2ab1"},
	}
	for _, tc := range cases {
		raw, err := hex.DecodeString(tc.hex)
		if err != nil {
			t.Fatal(err)
		}
		fp := fingerprintFromHello(raw, "")
		if fp.SNI != tc.sni || fp.JA4 != tc.ja4 {
			t.Errorf("%s: sni = %q ja4 = %q, want %q %q", tc.name, fp.SNI, fp.JA4, tc.sni, tc.ja4)
		}
	}
}

func TestJA4FoxIOSigalgGrease(t *testing.T) {
	t.Parallel()
	// sigalg-grease.pcapng offers 0x0a0a in signature_algorithms. The published
	// JA4 (t13d1517h2_8daaf6152771_cb7bf5808d99) does not contain it. The lists
	// below are the capture's, rebuilt synthetically because its ClientHello spans
	// several TCP segments.
	h, err := parseClientHello(helloSpec{
		version: 0x0303,
		ciphers: []uint16{0x4a4a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035},
		exts: []uint16{0x7a7a, 0xfe0d, 0x0010, 0x0017, 0x0033, 0x44cd, 0xff01, 0x000a, 0x000d, 0x0023, 0x002b, 0x000b,
			0xca34, 0x002d, 0x0000, 0x0005, 0x001b, 0x0012, 0xdada},
		sni:      "optimizationguide-pa.googleapis.com",
		sigAlgs:  []uint16{0x0a0a, 0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601},
		versions: []uint16{0xfafa, 0x0304, 0x0303},
		alpn:     []string{"h2", "http/1.1"},
	}.record())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := h.ja4(), "t13d1517h2_8daaf6152771_cb7bf5808d99"; got != want {
		t.Errorf("ja4 = %s, want %s", got, want)
	}
}

func TestJA4ALPNSpecExamples(t *testing.T) {
	t.Parallel()
	// technical_details/JA4.md of github.com/FoxIO-LLC/ja4.
	cases := map[string]string{
		"\xab":             "ab",
		"\x20":             "20",
		"\xab\xcd":         "ad",
		"\x20\x61":         "21",
		"\x30\xab":         "3b",
		"\x61\x20":         "60",
		"\x30\x31\xab\xcd": "3d",
		"\x30\xab\xcd\x31": "01",
		"h2":               "h2",
		"http/1.1":         "h1",
		"x":                "xx",
	}
	for in, want := range cases {
		if got := ja4ALPN([]string{in}); got != want {
			t.Errorf("ja4ALPN(%q) = %q, want %q", in, got, want)
		}
	}
	if ja4ALPN(nil) != "00" || ja4ALPN([]string{""}) != "00" {
		t.Error("missing ALPN must be 00")
	}
}

func TestJA4VersionUsesSupportedVersionsAlone(t *testing.T) {
	t.Parallel()
	cases := []struct {
		legacy   uint16
		versions []uint16
		want     string
	}{
		{0x0303, nil, "12"},
		{0x0303, []uint16{0x0304, 0x0303}, "13"},
		{0x0303, []uint16{0x7a7a, 0x0302, 0x0301}, "11"}, // the extension wins, not the legacy field
		{0x0303, []uint16{0x7a7a}, "12"},                 // only GREASE: legacy field
		{0x0301, nil, "10"},
	}
	for _, tc := range cases {
		h := &clientHello{Version: tc.legacy, Versions: tc.versions}
		if got := h.ja4Version(); got != tc.want {
			t.Errorf("legacy %#x versions %#x: got %s, want %s", tc.legacy, tc.versions, got, tc.want)
		}
	}
}
