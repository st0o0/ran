package trap

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/fingerprint"
	"github.com/st0o0/ran/internal/metrics"
)

// testProfile is the seeded profile the banner tests run against. The tests
// read every expected banner from it, never from a literal.
var testProfile = fingerprint.FromSeed(bytes.Repeat([]byte{0x42}, fingerprint.SeedSize))

// profileWhere returns the first seeded profile (over single-byte seeds) that
// satisfies pred.
func profileWhere(t testing.TB, pred func(*fingerprint.Profile) bool) *fingerprint.Profile {
	t.Helper()
	for i := range 256 {
		if p := fingerprint.FromSeed(bytes.Repeat([]byte{byte(i)}, fingerprint.SeedSize)); pred(p) {
			return p
		}
	}
	t.Fatal("no seed produces the wanted profile")
	return nil
}

func apacheTestProfile() *fingerprint.Profile {
	for i := range 256 {
		p := fingerprint.FromSeed(bytes.Repeat([]byte{byte(i)}, fingerprint.SeedSize))
		if p.HTTP.StatusServer != "" {
			return p
		}
	}
	panic("no Apache profile")
}

func profileConfig(name string, p *fingerprint.Profile) *config.Config {
	cfg := &config.Config{
		Addrs:          map[string]string{name: "127.0.0.1:0"},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
		MaxAuthRetries: 3,
	}
	if p != nil {
		cfg.SetFingerprint(p)
	}
	return cfg
}

func startProfileTrap(t *testing.T, name string, p *fingerprint.Profile, build func(*config.Config) Trap) string {
	t.Helper()
	cfg := profileConfig(name, p)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return serveTrap(t, ctx, build(cfg))
}

func firstLine(t *testing.T, addr string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	return line
}

func buildSSHForTest(t *testing.T) func(*config.Config) Trap {
	return func(cfg *config.Config) Trap {
		tr, err := NewSSH(cfg, quietLogger(), metrics.New(prometheus.NewRegistry(), "test"), NewLimiter(100, 10), alert.NoopAlerter{})
		if err != nil {
			t.Fatal(err)
		}
		return tr
	}
}

func TestSSHBannerComesFromTheProfile(t *testing.T) {
	t.Parallel()
	addr := startProfileTrap(t, "ssh", testProfile, buildSSHForTest(t))
	if got, want := firstLine(t, addr), testProfile.SSH+"\r\n"; got != want {
		t.Errorf("banner = %q, want %q", got, want)
	}
}

func TestFixedModeBannersAreUnchanged(t *testing.T) {
	t.Parallel()
	t.Run("ssh", func(t *testing.T) {
		t.Parallel()
		addr := startProfileTrap(t, "ssh", fingerprint.Fixed(), buildSSHForTest(t))
		if got := firstLine(t, addr); got != "SSH-2.0-OpenSSH_9.6\r\n" {
			t.Errorf("banner = %q", got)
		}
	})
	t.Run("literal config", func(t *testing.T) {
		t.Parallel()
		// A Config without a profile (not built by Load) behaves like fixed mode.
		addr := startProfileTrap(t, "ssh", nil, buildSSHForTest(t))
		if got := firstLine(t, addr); got != "SSH-2.0-OpenSSH_9.6\r\n" {
			t.Errorf("banner = %q", got)
		}
	})
	t.Run("mysql", func(t *testing.T) {
		t.Parallel()
		addr := startProfileTrap(t, "mysql", fingerprint.Fixed(), func(cfg *config.Config) Trap {
			return NewMySQL(cfg, quietLogger(), metrics.New(prometheus.NewRegistry(), "test"), NewLimiter(100, 10), alert.NoopAlerter{})
		})
		if got := mysqlGreetingVersion(t, addr); got != "8.0.36" {
			t.Errorf("version = %q", got)
		}
	})
	t.Run("smtp", func(t *testing.T) {
		t.Parallel()
		addr := startProfileTrap(t, "smtp", fingerprint.Fixed(), func(cfg *config.Config) Trap {
			return NewSMTP(cfg, quietLogger(), metrics.New(prometheus.NewRegistry(), "test"), NewLimiter(100, 10), alert.NoopAlerter{})
		})
		if got := firstLine(t, addr); got != "220 mx.localdomain ESMTP ready\r\n" {
			t.Errorf("banner = %q", got)
		}
	})
	t.Run("elasticsearch", func(t *testing.T) {
		t.Parallel()
		addr := startProfileTrap(t, "elasticsearch", fingerprint.Fixed(), func(cfg *config.Config) Trap {
			return NewElasticsearch(cfg, quietLogger(), metrics.New(prometheus.NewRegistry(), "test"), NewLimiter(100, 10), alert.NoopAlerter{})
		})
		got := httpBody(t, "http://"+addr+"/")
		const want = `{"name":"node-1","cluster_name":"elasticsearch","cluster_uuid":"_na_","version":{"number":"8.12.0","build_flavor":"default"},"tagline":"You Know, for Search"}`
		if got != want {
			t.Errorf("root = %s", got)
		}
		if got := httpBody(t, "http://"+addr+"/_cluster/health"); got != `{"cluster_name":"elasticsearch","status":"green","number_of_nodes":1}` {
			t.Errorf("health = %s", got)
		}
	})
	t.Run("http", func(t *testing.T) {
		t.Parallel()
		addr := startProfileTrap(t, "http", fingerprint.Fixed(), func(cfg *config.Config) Trap {
			return NewHTTP(cfg, quietLogger(), metrics.New(prometheus.NewRegistry(), "test"), NewLimiter(100, 10), alert.NoopAlerter{})
		})
		resp := fxDo(t, false, addr, "GET", "/admin", nil, "")
		if resp.header.Get("Server") != "Apache/2.4.62" || resp.header.Get("X-Powered-By") != "PHP/8.3.6" {
			t.Errorf("headers = %v", resp.header)
		}
		if got := fxDo(t, false, addr, "GET", "/server-status", nil, ""); !strings.Contains(got.body, "Server Version: Apache/2.4.62 (Unix)") {
			t.Errorf("server-status = %q", got.body)
		}
		if got := fxDo(t, false, addr, "GET", "/phpinfo.php", nil, ""); !strings.Contains(got.body, "PHP Version 8.3.6") || !strings.Contains(got.body, "Apache 2.0 Handler") {
			t.Errorf("phpinfo = %q", got.body)
		}
	})
}

func httpBody(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func mysqlGreetingVersion(t *testing.T, addr string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, int(hdr[0])|int(hdr[1])<<8|int(hdr[2])<<16)
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatal(err)
	}
	end := bytes.IndexByte(payload[1:], 0)
	if payload[0] != 10 || end < 0 {
		t.Fatalf("bad greeting %q", payload)
	}
	return string(payload[1 : 1+end])
}

func TestMySQLGreetingOnTheWireComesFromTheProfile(t *testing.T) {
	t.Parallel()
	addr := startProfileTrap(t, "mysql", testProfile, func(cfg *config.Config) Trap {
		return NewMySQL(cfg, quietLogger(), metrics.New(prometheus.NewRegistry(), "test"), NewLimiter(100, 10), alert.NoopAlerter{})
	})
	if got := mysqlGreetingVersion(t, addr); got != testProfile.MySQL {
		t.Errorf("version = %q, want %q", got, testProfile.MySQL)
	}
}

func TestSeedsGiveDifferentBannersOnTheWire(t *testing.T) {
	t.Parallel()
	a := fingerprint.FromSeed(bytes.Repeat([]byte{1}, fingerprint.SeedSize))
	b := profileWhere(t, func(p *fingerprint.Profile) bool { return p.SSH != a.SSH })
	got := map[string]bool{}
	for _, p := range []*fingerprint.Profile{a, b} {
		addr := startProfileTrap(t, "ssh", p, buildSSHForTest(t))
		got[firstLine(t, addr)] = true
	}
	if len(got) != 2 {
		t.Errorf("banners = %v, want two different ones", got)
	}
}

// startHTTPFamily starts the http or https trap on profile p.
func startHTTPFamily(t *testing.T, proto string, p *fingerprint.Profile) string {
	t.Helper()
	addr, _ := startSensorTrap(t, proto, func(cfg *config.Config, l *slog.Logger, m *metrics.Metrics, lim *Limiter, r Reporter) Trap {
		cfg.SetFingerprint(p)
		if proto == "https" {
			return newHTTPSTrap(t, cfg, r, lim)
		}
		return NewHTTP(cfg, l, m, lim, r)
	})
	return addr
}

func TestHTTPServerHeaderParityAcrossHTTPHTTPSAndFixtures(t *testing.T) {
	t.Parallel()
	profiles := map[string]*fingerprint.Profile{
		"apache": apacheTestProfile(),
		"nginx":  profileWhere(t, func(p *fingerprint.Profile) bool { return p.HTTP.StatusServer == "" }),
	}
	for name, p := range profiles {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			paths := []string{"/", "/admin", "/wp-login.php", "/robots.txt", "/.env", "/phpinfo.php", "/actuator/health", "/server-status", "/wp-json/"}
			for _, proto := range []string{"http", "https"} {
				addr := startHTTPFamily(t, proto, p)
				for _, path := range paths {
					got := fxDo(t, proto == "https", addr, "GET", path, nil, "")
					if s := got.header.Get("Server"); s != p.HTTP.Server {
						t.Errorf("%s %s: Server = %q, want %q", proto, path, s, p.HTTP.Server)
					}
				}
				if got := fxDo(t, proto == "https", addr, "GET", "/phpinfo.php", nil, ""); got.header.Get("X-Powered-By") != p.HTTP.PoweredBy() ||
					!strings.Contains(got.body, "PHP Version "+p.HTTP.PHP) {
					t.Errorf("%s phpinfo: header %q body %q", proto, got.header.Get("X-Powered-By"), got.body)
				}
				if got := fxDo(t, proto == "https", addr, "GET", "/admin", nil, ""); got.header.Get("X-Powered-By") != p.HTTP.PoweredBy() {
					t.Errorf("%s login page X-Powered-By = %q", proto, got.header.Get("X-Powered-By"))
				}
				status := fxDo(t, proto == "https", addr, "GET", "/server-status", nil, "")
				if p.HTTP.StatusServer != "" {
					if !strings.Contains(status.body, "Server Version: "+p.HTTP.StatusServer+"<") {
						t.Errorf("%s server-status lacks the profile version: %q", proto, status.body)
					}
				} else if strings.Contains(status.body, "Apache") {
					t.Errorf("%s: nginx profile serves an Apache status page: %q", proto, status.body)
				}
			}
		})
	}
}

func TestOperatorFixtureCanStillSetItsOwnServer(t *testing.T) {
	t.Parallel()
	p := apacheTestProfile()
	addr, _ := startSensorTrap(t, "http", func(cfg *config.Config, l *slog.Logger, m *metrics.Metrics, lim *Limiter, r Reporter) Trap {
		cfg.SetFingerprint(p)
		cfg.HTTPFixtures = []config.HTTPFixture{{Path: "/custom", Status: 200, Headers: map[string]string{"Server": "custom/1"}, Body: "x"}}
		return NewHTTP(cfg, l, m, lim, r)
	})
	if got := fxDo(t, false, addr, "GET", "/custom", nil, "").header.Get("Server"); got != "custom/1" {
		t.Errorf("operator Server = %q", got)
	}
}

func TestSMTPBannerAndEHLOFromTheProfile(t *testing.T) {
	t.Parallel()
	p := testProfile
	addr := startProfileTrap(t, "smtp", p, func(cfg *config.Config) Trap {
		return NewSMTP(cfg, quietLogger(), metrics.New(prometheus.NewRegistry(), "test"), NewLimiter(100, 10), alert.NoopAlerter{})
	})
	conn, r := dialSMTP(t, addr)
	defer conn.Close()
	if got := readLine(t, r); got != p.SMTP.Greeting()+"\r\n" {
		t.Errorf("banner = %q", got)
	}
	_, _ = conn.Write([]byte("EHLO test\r\n"))
	if got := readLine(t, r); got != "250-"+p.SMTP.Host+"\r\n" {
		t.Errorf("ehlo = %q", got)
	}
}

func TestElasticsearchFieldsAreConsistent(t *testing.T) {
	t.Parallel()
	p := testProfile
	addr := startProfileTrap(t, "elasticsearch", p, func(cfg *config.Config) Trap {
		return NewElasticsearch(cfg, quietLogger(), metrics.New(prometheus.NewRegistry(), "test"), NewLimiter(100, 10), alert.NoopAlerter{})
	})
	var root, health map[string]any
	if err := json.Unmarshal([]byte(httpBody(t, "http://"+addr+"/")), &root); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(httpBody(t, "http://"+addr+"/_cluster/health")), &health); err != nil {
		t.Fatal(err)
	}
	if root["cluster_name"] != health["cluster_name"] || root["cluster_name"] != p.Elasticsearch.ClusterName {
		t.Errorf("cluster names differ: root %v health %v profile %q", root["cluster_name"], health["cluster_name"], p.Elasticsearch.ClusterName)
	}
}

// metaReporter records the meta of every alert exactly as the trap built it.
type metaReporter struct {
	mu    sync.Mutex
	metas []map[string]string
}

func (r *metaReporter) Alert(_ context.Context, _ alert.SessionInfo, meta map[string]string) alert.Class {
	cp := make(map[string]string, len(meta))
	for k, v := range meta {
		cp[k] = v
	}
	r.mu.Lock()
	r.metas = append(r.metas, cp)
	r.mu.Unlock()
	return alert.ClassAttack
}

func (r *metaReporter) SessionEnd(alert.SessionInfo) bool { return false }

func (r *metaReporter) wait(t *testing.T, n int) []map[string]string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		r.mu.Lock()
		got := append([]map[string]string(nil), r.metas...)
		r.mu.Unlock()
		if len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d alerts, have %v", n, got)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func sortedKeys(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

// kindCase drives one trap to its alert(s). Each want entry is the exact key
// set and kind of the n-th alert.
type kindCase struct {
	name  string
	build func(cfg *config.Config, rep Reporter) Trap
	drive func(t *testing.T, conn net.Conn)
	want  []struct{ keys, kind string }
}

func TestKindMetaPerSingleRequestTrap(t *testing.T) {
	t.Parallel()
	newM := func() *metrics.Metrics { return metrics.New(prometheus.NewRegistry(), "test") }
	lim := func() *Limiter { return NewLimiter(100, 10) }
	cases := []kindCase{
		{
			name:  "vnc",
			build: func(c *config.Config, r Reporter) Trap { return NewVNC(c, quietLogger(), newM(), lim(), r) },
			drive: func(t *testing.T, conn net.Conn) {
				mustRead(t, conn, 12)
				mustWrite(t, conn, []byte("RFB 003.008\n"))
				mustRead(t, conn, 2)
				mustWrite(t, conn, []byte{2})
				mustRead(t, conn, 16)
				mustWrite(t, conn, make([]byte, 16))
			},
			want: []struct{ keys, kind string }{{"kind", "auth_response"}},
		},
		{
			name:  "rdp",
			build: func(c *config.Config, r Reporter) Trap { return NewRDP(c, quietLogger(), newM(), lim(), r) },
			drive: func(t *testing.T, conn net.Conn) { mustWrite(t, conn, buildRDPConnectionRequest("administrator")) },
			want:  []struct{ keys, kind string }{{"kind,username", "connection_request"}},
		},
		{
			name:  "oracle",
			build: func(c *config.Config, r Reporter) Trap { return NewOracle(c, quietLogger(), newM(), lim(), r) },
			drive: func(t *testing.T, conn net.Conn) {
				mustWrite(t, conn, buildTNSPacket(1, []byte("(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=ORCL))(USER=scott))")))
			},
			want: []struct{ keys, kind string }{{"kind,service_name,username", "connect"}},
		},
		{
			name:  "mqtt",
			build: func(c *config.Config, r Reporter) Trap { return NewMQTT(c, quietLogger(), newM(), lim(), r) },
			drive: func(t *testing.T, conn net.Conn) {
				mustWrite(t, conn, buildMQTTConnectPacket("MQTT", 4, "cid", "user", "pw"))
			},
			want: []struct{ keys, kind string }{{"client_id,kind,password,username", "connect"}},
		},
		{
			name:  "modbus write",
			build: func(c *config.Config, r Reporter) Trap { return NewModbus(c, quietLogger(), newM(), lim(), r) },
			drive: func(t *testing.T, conn net.Conn) {
				mustWrite(t, conn, buildModbusRequest(1, 1, 6, []byte{0, 0x10, 0, 0xFF}))
			},
			want: []struct{ keys, kind string }{{"address,function_code,kind,value", "write"}},
		},
		{
			name:  "modbus unknown function",
			build: func(c *config.Config, r Reporter) Trap { return NewModbus(c, quietLogger(), newM(), lim(), r) },
			drive: func(t *testing.T, conn net.Conn) {
				mustWrite(t, conn, buildModbusRequest(1, 1, 90, []byte{1, 2}))
			},
			want: []struct{ keys, kind string }{{"function_code,kind", "unknown_function"}},
		},
		{
			name:  "minecraft status",
			build: func(c *config.Config, r Reporter) Trap { return NewMinecraft(c, quietLogger(), newM(), lim(), r) },
			drive: func(t *testing.T, conn net.Conn) {
				mustWrite(t, conn, mcBuildHandshake(765, "host", 25565, 1))
				mustWrite(t, conn, mcBuildPacket(0x00, nil))
				// The status handler waits for a ping; hang up so the session ends.
				_ = conn.Close()
			},
			want:  []struct{ keys, kind string }{{"kind,protocol_version,server_address", "status"}},
		},
		{
			name:  "minecraft login",
			build: func(c *config.Config, r Reporter) Trap { return NewMinecraft(c, quietLogger(), newM(), lim(), r) },
			drive: func(t *testing.T, conn net.Conn) {
				mustWrite(t, conn, mcBuildHandshake(765, "host", 25565, 2))
				mustWrite(t, conn, mcBuildPacket(0x00, mcWriteString("Steve")))
			},
			want: []struct{ keys, kind string }{{"kind,player_name,protocol_version,server_address", "login"}},
		},
		{
			name:  "minecraft handshake only",
			build: func(c *config.Config, r Reporter) Trap { return NewMinecraft(c, quietLogger(), newM(), lim(), r) },
			drive: func(t *testing.T, conn net.Conn) { mustWrite(t, conn, mcBuildHandshake(765, "host", 25565, 3)) },
			want:  []struct{ keys, kind string }{{"kind,protocol_version,server_address", "handshake"}},
		},
		{
			name:  "adb connect and shell command",
			build: func(c *config.Config, r Reporter) Trap { return NewADB(c, quietLogger(), newM(), lim(), r) },
			drive: func(t *testing.T, conn net.Conn) {
				adbHandshake(t, conn)
				mustWrite(t, conn, adbPacket(adbCmdOPEN, 7, 0, []byte("shell:id")))
			},
			want: []struct{ keys, kind string }{{"identity,kind", "connect"}, {"command,kind", "shell_command"}},
		},
		{
			name:  "adb public key",
			build: func(c *config.Config, r Reporter) Trap { return NewADB(c, quietLogger(), newM(), lim(), r) },
			drive: func(t *testing.T, conn net.Conn) {
				adbHandshake(t, conn)
				mustWrite(t, conn, adbPacket(adbCmdAUTH, adbAuthPublicKey, 0, []byte("key-material")))
			},
			want: []struct{ keys, kind string }{{"identity,kind", "connect"}, {"key_hash,kind,method", "auth"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rep := &metaReporter{}
			cfg := profileConfig("vnc", nil)
			for _, n := range []string{"rdp", "oracle", "mqtt", "modbus", "minecraft", "adb"} {
				cfg.Addrs[n] = "127.0.0.1:0"
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			addr := serveTrap(t, ctx, tc.build(cfg, rep))
			conn := dialTrap(t, addr)
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
			tc.drive(t, conn)
			got := rep.wait(t, len(tc.want))
			for i, w := range tc.want {
				if keys := sortedKeys(got[i]); keys != w.keys {
					t.Errorf("alert %d: keys = %s, want %s", i, keys, w.keys)
				}
				if got[i]["kind"] != w.kind {
					t.Errorf("alert %d: kind = %q, want %q", i, got[i]["kind"], w.kind)
				}
				// The sensor adds a handful of keys; stay well below the cap of 32.
				if len(got[i]) > 20 {
					t.Errorf("alert %d: %d meta keys", i, len(got[i]))
				}
			}
		})
	}
}

func mustWrite(t *testing.T, conn net.Conn, b []byte) {
	t.Helper()
	if _, err := conn.Write(b); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, conn net.Conn, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	return buf
}

// mcBuildPacket frames a Minecraft packet: varint length, packet id, data.
func mcBuildPacket(id byte, data []byte) []byte {
	payload := append([]byte{id}, data...)
	return append(mcWriteVarint(int32(len(payload))), payload...)
}

func TestModbusReadStaysSilentWithoutAlert(t *testing.T) {
	t.Parallel()
	rep := &metaReporter{}
	cfg := profileConfig("modbus", nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := serveTrap(t, ctx, NewModbus(cfg, quietLogger(), metrics.New(prometheus.NewRegistry(), "test"), NewLimiter(100, 10), rep))
	conn := dialTrap(t, addr)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	req := make([]byte, 4)
	binary.BigEndian.PutUint16(req[2:], 1)
	mustWrite(t, conn, buildModbusRequest(1, 1, 3, req))
	mustRead(t, conn, 9)
	rep.mu.Lock()
	defer rep.mu.Unlock()
	if len(rep.metas) != 0 {
		t.Errorf("read request alerted: %v", rep.metas)
	}
}
