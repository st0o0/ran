package trap

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/fingerprint"
	"github.com/st0o0/ran/internal/metrics"
)

// legacyGreeting writes the pre-profile greeting out literally, independent of
// buildGreeting: capability flags 0x8209/0x0008, charset utf8 (0x21).
func legacyGreeting(version string, connID uint32, ch []byte) []byte {
	var p []byte
	p = append(p, 10)
	p = append(p, version...)
	p = append(p, 0)
	p = binary.LittleEndian.AppendUint32(p, connID)
	p = append(p, ch[:8]...)
	p = append(p, 0, 0x09, 0x82, 0x21, 0x02, 0x00, 0x08, 0x00, 21)
	p = append(p, make([]byte, 10)...)
	p = append(p, ch[8:]...)
	p = append(p, 0)
	p = append(p, "mysql_clear_password\x00"...)
	return append([]byte{byte(len(p)), byte(len(p) >> 8), byte(len(p) >> 16), 0}, p...)
}

func mysqlProfile(mode, version string) *fingerprint.Profile {
	p := *fingerprint.Fixed()
	p.Mode = mode
	p.MySQL = version
	return &p
}

func startMySQLProfile(t *testing.T, p *fingerprint.Profile, retries int, rec Reporter) string {
	t.Helper()
	cfg := profileConfig("mysql", p)
	cfg.MaxAuthRetries = retries
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return serveTrap(t, ctx, NewMySQL(cfg, quietLogger(), metrics.New(prometheus.NewRegistry(), "test"), NewLimiter(100, 10), rec))
}

func readMySQL(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	pkt, err := readMySQLPacket(conn)
	if err != nil {
		t.Fatal(err)
	}
	return pkt
}

type greetingFields struct {
	version        string
	capLow, capHi  uint16
	charset        byte
	plugin         string
	scramble       []byte
	authDataLength byte
}

func parseGreeting(t *testing.T, p []byte) greetingFields {
	t.Helper()
	var g greetingFields
	end := bytes.IndexByte(p[1:], 0) + 1
	g.version = string(p[1:end])
	pos := end + 1 + 4
	s1 := p[pos : pos+8]
	pos += 8 + 1
	g.capLow = binary.LittleEndian.Uint16(p[pos:])
	g.charset = p[pos+2]
	g.capHi = binary.LittleEndian.Uint16(p[pos+5:])
	g.authDataLength = p[pos+7]
	pos += 8 + 10
	g.scramble = append(append([]byte(nil), s1...), p[pos:pos+12]...)
	pos += 13
	g.plugin = string(bytes.TrimRight(p[pos:], "\x00"))
	return g
}

func TestMySQLFixedGreetingKeepsTheOldBytes(t *testing.T) {
	t.Parallel()
	ch := make([]byte, 20)
	for i := range ch {
		ch[i] = byte(i + 1)
	}
	if got, want := buildGreeting("8.0.36", 1, ch), legacyGreeting("8.0.36", 1, ch); !bytes.Equal(got, want) {
		t.Fatalf("buildGreeting changed:\n got  %x\n want %x", got, want)
	}

	// On the wire in fixed mode: the old greeting, with the random scramble.
	addr := startMySQLProfile(t, fingerprint.Fixed(), 3, alert.NoopAlerter{})
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, int(hdr[0])|int(hdr[1])<<8|int(hdr[2])<<16)
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatal(err)
	}
	g := parseGreeting(t, payload)
	want := legacyGreeting("8.0.36", 1, g.scramble)
	if got := append(hdr[:], payload...); !bytes.Equal(got, want) {
		t.Errorf("fixed greeting on the wire differs:\n got  %x\n want %x", got, want)
	}
}

func TestMySQLRealisticGreetingPerGeneration(t *testing.T) {
	t.Parallel()
	ch := bytes.Repeat([]byte{7}, 20)
	cases := []struct {
		version string
		capHi   uint16
		charset byte
		plugin  string
	}{
		{"8.0.35", 0xc3ff, 0xff, "caching_sha2_password"},
		{"8.0.40-0ubuntu0.24.04.1", 0xc3ff, 0xff, "caching_sha2_password"},
		{"5.7.44", 0x807f, 0x08, "mysql_native_password"},
		{"5.7.42-0ubuntu0.18.04.1", 0x807f, 0x08, "mysql_native_password"},
	}
	for _, c := range cases {
		pkt := buildRealisticGreeting(c.version, 5, ch)
		if int(pkt[0])|int(pkt[1])<<8|int(pkt[2])<<16 != len(pkt)-4 || pkt[3] != 0 {
			t.Fatalf("%s: bad framing", c.version)
		}
		g := parseGreeting(t, pkt[4:])
		if g.version != c.version || g.capLow != 0xf7ff || g.capHi != c.capHi || g.charset != c.charset || g.plugin != c.plugin || g.authDataLength != 21 {
			t.Errorf("%s: %+v", c.version, g)
		}
		if g.capLow&0x0800 != 0 {
			t.Errorf("%s: advertises CLIENT_SSL although the trap has no TLS", c.version)
		}
		if g.capHi&0x0008 == 0 {
			t.Errorf("%s: no CLIENT_PLUGIN_AUTH", c.version)
		}
		if !bytes.Equal(g.scramble, ch) {
			t.Errorf("%s: scramble %x", c.version, g.scramble)
		}
	}
}

// scrambleResponse is a HandshakeResponse41 as a real client sends it: a
// 20 byte scramble and the auth plugin name.
func scrambleResponse(user, plugin string) []byte {
	var r []byte
	r = binary.LittleEndian.AppendUint32(r, 0x00000200|0x00008000|0x00080000|0x00200000|0x00000008)
	r = binary.LittleEndian.AppendUint32(r, 1<<24)
	r = append(r, 0xff)
	r = append(r, make([]byte, 23)...)
	r = append(r, user...)
	r = append(r, 0, 20)
	r = append(r, bytes.Repeat([]byte{0xaa}, 20)...)
	r = append(r, "db\x00"...)
	r = append(r, plugin...)
	r = append(r, 0)
	return r
}

func TestMySQLRealisticGreetingStillCapturesThePassword(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ version, plugin string }{
		{"8.0.39", "caching_sha2_password"},
		{"5.7.44", "mysql_native_password"},
	} {
		t.Run(c.version, func(t *testing.T) {
			t.Parallel()
			rec := &recordingAlerter{}
			addr := startMySQLProfile(t, mysqlProfile(fingerprint.ModeSeeded, c.version), 1, rec)
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			if g := parseGreeting(t, readMySQL(t, conn)); g.plugin != c.plugin || g.version != c.version {
				t.Fatalf("greeting %+v", g)
			}
			if _, err := conn.Write(wrapMySQLPacket(1, scrambleResponse("root", c.plugin))); err != nil {
				t.Fatal(err)
			}
			sw := readMySQL(t, conn)
			if sw[0] != 0xFE || string(sw[1:]) != "mysql_clear_password\x00" {
				t.Fatalf("expected an auth switch to mysql_clear_password, got %q", sw)
			}
			if _, err := conn.Write(wrapMySQLPacket(3, []byte("hunter2\x00"))); err != nil {
				t.Fatal(err)
			}
			if resp := readMySQL(t, conn); resp[0] != 0xFF {
				t.Fatalf("expected ERR, got %x", resp)
			}

			var user, pass []string
			for _, a := range rec.snapshot() {
				user = append(user, a.Meta["username"])
				pass = append(pass, a.Meta["password"])
			}
			// The scramble is no credential: exactly one record, the clear text.
			if len(pass) != 1 || pass[0] != "hunter2" || user[0] != "root" {
				t.Errorf("captured %q / %q, want exactly root / hunter2", user, pass)
			}
		})
	}
}

func TestMySQLClientPluginName(t *testing.T) {
	t.Parallel()
	if got := mysqlClientPluginName(scrambleResponse("u", "caching_sha2_password")); got != "caching_sha2_password" {
		t.Errorf("plugin = %q", got)
	}
	r := scrambleResponse("u", "x")
	for n := range len(r) { // no truncation may panic
		_ = mysqlClientPluginName(r[:n])
	}
	if got := mysqlClientPluginName(nil); got != "" {
		t.Errorf("plugin of nil = %q", got)
	}
}
