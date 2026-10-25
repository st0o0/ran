package trap

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/fingerprint"
	"github.com/st0o0/ran/internal/metrics"
)

var mysqlScrambleCases = []struct{ version, plugin string }{
	{"8.0.39", "caching_sha2_password"},
	{"5.7.44", "mysql_native_password"},
}

// startMySQLScramble starts a MySQL trap with the given profile and a recording
// reporter, so a test sees the alert meta as well as the logs and the metrics.
func startMySQLScramble(t *testing.T, p *fingerprint.Profile, retries int) (*depthTrap, *recordingAlerter) {
	t.Helper()
	rec := &recordingAlerter{}
	d := startDepthTrap(t, "mysql", func(c *config.Config) {
		c.MaxAuthRetries = retries
		c.SetFingerprint(p)
	}, func(c *config.Config, l *slog.Logger, m *metrics.Metrics, lim *Limiter, _ Reporter) Trap {
		return NewMySQL(c, l, m, lim, rec)
	})
	return d, rec
}

// authAttemptLines returns the auth_attempt log lines of the trap.
func authAttemptLines(t *testing.T, d *depthTrap) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(d.logs.String(), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("bad log line %q: %v", line, err)
		}
		if rec["action"] == "auth_attempt" {
			out = append(out, rec)
		}
	}
	return out
}

// scrambleToSwitch connects, answers the greeting with a scramble and returns
// the connection after the trap's authentication switch request.
func scrambleToSwitch(t *testing.T, d *depthTrap, user, plugin string) net.Conn {
	t.Helper()
	conn := dialTrap(t, d.addr)
	readMySQLFrame(t, conn) // greeting
	if _, err := conn.Write(wrapMySQLPacket(1, scrambleResponse(user, plugin))); err != nil {
		t.Fatal(err)
	}
	_, sw := readMySQLFrame(t, conn)
	if sw[0] != 0xFE || string(sw[1:]) != "mysql_clear_password\x00" {
		t.Fatalf("expected an auth switch to mysql_clear_password, got %q", sw)
	}
	return conn
}

func TestMySQLScrambleThenClearPasswordIsOneCredential(t *testing.T) {
	t.Parallel()
	for _, c := range mysqlScrambleCases {
		t.Run(c.version, func(t *testing.T) {
			t.Parallel()
			d, rec := startMySQLScramble(t, mysqlProfile(fingerprint.ModeSeeded, c.version), 3)
			conn := scrambleToSwitch(t, d, "root", c.plugin)
			if _, err := conn.Write(wrapMySQLPacket(3, []byte("hunter2\x00"))); err != nil {
				t.Fatal(err)
			}
			// Three attempts are allowed, so the trap asks again; end the session.
			_, next := readMySQLFrame(t, conn)
			if next[0] != 0xFE {
				t.Fatalf("expected a further switch, got %x", next)
			}
			conn.Close()
			d.waitOutcomeLabel(t, "mysql", "completed")

			if got := d.credentials("mysql"); got != 1 {
				t.Errorf("credentials = %v, want 1", got)
			}
			alerts := rec.snapshot()
			if len(alerts) != 1 || alerts[0].Meta["username"] != "root" || alerts[0].Meta["password"] != "hunter2" {
				t.Errorf("alerts = %+v, want exactly one with root/hunter2", alerts)
			}
			if lines := authAttemptLines(t, d); len(lines) != 1 || lines[0]["username"] != "root" {
				t.Errorf("auth_attempt lines = %v, want exactly one for root", lines)
			}
		})
	}
}

// The switch round is not a password attempt: with RAN_MAX_AUTH_RETRIES=1 the
// clear text is still asked for, and exactly one password counts.
func TestMySQLScrambleSwitchDoesNotUseUpRetries(t *testing.T) {
	t.Parallel()
	d, rec := startMySQLScramble(t, mysqlProfile(fingerprint.ModeSeeded, "8.0.39"), 1)
	conn := scrambleToSwitch(t, d, "root", "caching_sha2_password")
	if _, err := conn.Write(wrapMySQLPacket(3, []byte("hunter2\x00"))); err != nil {
		t.Fatal(err)
	}
	if _, resp := readMySQLFrame(t, conn); resp[0] != 0xFF {
		t.Fatalf("expected ERR, got %x", resp)
	}
	d.waitOutcomeLabel(t, "mysql", "completed")
	if got := d.credentials("mysql"); got != 1 {
		t.Errorf("credentials = %v, want 1", got)
	}
	if a := rec.snapshot(); len(a) != 1 || a[0].Meta["password"] != "hunter2" {
		t.Errorf("alerts = %+v", a)
	}
}

// Retries count real passwords only and the repeat password guard still works.
func TestMySQLScrambleRetriesAndRepeatGuard(t *testing.T) {
	t.Parallel()
	d, rec := startMySQLScramble(t, mysqlProfile(fingerprint.ModeSeeded, "5.7.44"), 3)
	conn := scrambleToSwitch(t, d, "root", "mysql_native_password")
	seq := byte(3)
	for _, pw := range []string{"one", "two"} {
		if _, err := conn.Write(wrapMySQLPacket(seq, []byte(pw+"\x00"))); err != nil {
			t.Fatal(err)
		}
		seq += 2
		if _, p := readMySQLFrame(t, conn); p[0] != 0xFE {
			t.Fatalf("after %q: want a further switch, got %x", pw, p)
		}
	}
	// A repeated password is not a new attempt and ends the session.
	if _, err := conn.Write(wrapMySQLPacket(seq, []byte("two\x00"))); err != nil {
		t.Fatal(err)
	}
	if _, p := readMySQLFrame(t, conn); p[0] != 0xFF {
		t.Fatalf("repeat: want ERR, got %x", p)
	}
	d.waitOutcomeLabel(t, "mysql", "completed")
	if got := d.credentials("mysql"); got != 2 {
		t.Errorf("credentials = %v, want 2", got)
	}
	var pws []string
	for _, a := range rec.snapshot() {
		pws = append(pws, a.Meta["password"])
	}
	if fmt.Sprint(pws) != "[one two]" {
		t.Errorf("passwords = %q, want [one two]", pws)
	}
}

func TestMySQLScrambleClientHangsUp(t *testing.T) {
	t.Parallel()
	for _, c := range mysqlScrambleCases {
		t.Run(c.version, func(t *testing.T) {
			t.Parallel()
			d, rec := startMySQLScramble(t, mysqlProfile(fingerprint.ModeSeeded, c.version), 3)
			conn := scrambleToSwitch(t, d, "root", c.plugin)
			conn.Close()
			d.waitOutcomeLabel(t, "mysql", "completed")
			assertNoPasswordAttempt(t, d, rec, "root")
		})
	}
}

func TestMySQLScrambleClientRefusesTheSwitch(t *testing.T) {
	t.Parallel()
	for _, c := range mysqlScrambleCases {
		t.Run(c.version, func(t *testing.T) {
			t.Parallel()
			d, rec := startMySQLScramble(t, mysqlProfile(fingerprint.ModeSeeded, c.version), 3)
			conn := scrambleToSwitch(t, d, "root", c.plugin)
			// A second scramble: 20 bytes, not NUL terminated.
			if _, err := conn.Write(wrapMySQLPacket(3, bytes.Repeat([]byte{0xaa}, 20))); err != nil {
				t.Fatal(err)
			}
			if s, p := readMySQLFrame(t, conn); p[0] != 0xFF || s != 4 {
				t.Fatalf("want ERR seq 4, got 0x%02x seq %d", p[0], s)
			}
			d.waitOutcomeLabel(t, "mysql", "completed")
			assertNoPasswordAttempt(t, d, rec, "root")
		})
	}
}

// assertNoPasswordAttempt checks the rule for a login without a known password:
// one auth_attempt line without a password, one credential, one alert with the
// username and no password.
func assertNoPasswordAttempt(t *testing.T, d *depthTrap, rec *recordingAlerter, user string) {
	t.Helper()
	if got := d.credentials("mysql"); got != 1 {
		t.Errorf("credentials = %v, want 1", got)
	}
	lines := authAttemptLines(t, d)
	if len(lines) != 1 || lines[0]["username"] != user {
		t.Fatalf("auth_attempt lines = %v, want exactly one for %s", lines, user)
	}
	if _, ok := lines[0]["password"]; ok {
		t.Errorf("auth_attempt carries a password: %v", lines[0])
	}
	alerts := rec.snapshot()
	if len(alerts) != 1 || alerts[0].Meta["username"] != user {
		t.Fatalf("alerts = %+v, want exactly one for %s", alerts, user)
	}
	if _, ok := alerts[0].Meta["password"]; ok {
		t.Errorf("alert meta carries a password: %v", alerts[0].Meta)
	}
}

// With an empty username the attempt is logged but neither counted nor alerted.
func TestMySQLScrambleEmptyUsernameIsNotACredential(t *testing.T) {
	t.Parallel()
	d, rec := startMySQLScramble(t, mysqlProfile(fingerprint.ModeSeeded, "8.0.39"), 3)
	conn := scrambleToSwitch(t, d, "", "caching_sha2_password")
	conn.Close()
	d.waitOutcomeLabel(t, "mysql", "completed")
	if got := d.credentials("mysql"); got != 0 {
		t.Errorf("credentials = %v, want 0", got)
	}
	if n := len(rec.snapshot()); n != 0 {
		t.Errorf("alerts = %d, want 0", n)
	}
	if lines := authAttemptLines(t, d); len(lines) != 1 {
		t.Errorf("auth_attempt lines = %d, want 1", len(lines))
	}
}

// Fixed mode is unchanged: the clear password comes in the first response and is
// the only credential.
func TestMySQLFixedModeStaysOneClearCredential(t *testing.T) {
	t.Parallel()
	d, rec := startMySQLScramble(t, fingerprint.Fixed(), 1)
	conn := dialTrap(t, d.addr)
	readMySQLFrame(t, conn)
	if _, err := conn.Write(mysqlLoginPacket("root", "hunter2")); err != nil {
		t.Fatal(err)
	}
	if _, p := readMySQLFrame(t, conn); p[0] != 0xFF {
		t.Fatalf("want ERR, got %x", p)
	}
	d.waitOutcomeLabel(t, "mysql", "completed")
	if got := d.credentials("mysql"); got != 1 {
		t.Errorf("credentials = %v, want 1", got)
	}
	if a := rec.snapshot(); len(a) != 1 || a[0].Meta["username"] != "root" || a[0].Meta["password"] != "hunter2" {
		t.Errorf("alerts = %+v", a)
	}
}

// End to end with the real CrowdSec sink: a seeded session that follows the
// switch produces exactly one alert, and the password never leaves the sensor.
func TestMySQLScrambleEndToEndOneCrowdSecAlert(t *testing.T) {
	lapi := &fakeLAPI{}
	srv := httptest.NewServer(lapi.handler())
	defer srv.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := metrics.New(prometheus.NewRegistry(), "test")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sink, err := alert.NewCrowdSec(ctx, alert.CrowdSecConfig{
		URL: srv.URL, MachineID: "ran", Password: "lapi-secret", BatchInterval: 50 * time.Millisecond, BatchSize: 1,
	}, logger, m)
	if err != nil {
		t.Fatal(err)
	}
	sensor := alert.NewSensor(alert.SensorConfig{SummaryWindow: time.Hour}, sink, logger)
	defer sensor.Close()

	cfg := &config.Config{
		Addrs:          map[string]string{"mysql": "127.0.0.1:0"},
		PerProto:       make(map[string]config.ProtoConfig),
		ProxyProtocol:  true,
		ProxyTrusted:   loopbackPrefixes,
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
		MaxAuthRetries: 1,
	}
	cfg.SetFingerprint(mysqlProfile(fingerprint.ModeSeeded, "8.0.39"))
	addr := serveTrap(t, ctx, NewMySQL(cfg, logger, m, NewLimiter(cfg.MaxSessions, cfg.MaxPerIP), sensor))

	session := func(ip string) {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(conn, "PROXY TCP4 %s 127.0.0.1 40000 3306\r\n", ip)
		readMySQLFrame(t, conn)
		_, _ = conn.Write(wrapMySQLPacket(1, scrambleResponse("root", "caching_sha2_password")))
		readMySQLFrame(t, conn) // auth switch
		_, _ = conn.Write(wrapMySQLPacket(3, []byte("hunter2\x00")))
		if _, p := readMySQLFrame(t, conn); p[0] != 0xFF {
			t.Errorf("want ERR, got %x", p)
		}
	}
	session("8.8.8.8")
	waitFor(t, func() bool { return lapi.acceptedCount() >= 1 })
	// A second source after the first one: once its alert arrived, anything the
	// first session would still have pushed has been flushed as well.
	session("1.1.1.1")
	waitFor(t, func() bool { return lapi.acceptedCount() >= 2 })

	lapi.mu.Lock()
	defer lapi.mu.Unlock()
	perIP := map[string]int{}
	for _, batch := range lapi.accepted {
		for _, a := range batch {
			src, _ := a["source"].(map[string]any)
			ip, _ := src["value"].(string)
			perIP[ip]++
			if a["scenario"] != "custom/ran-mysql-trap" {
				t.Errorf("scenario = %v", a["scenario"])
			}
		}
	}
	if perIP["8.8.8.8"] != 1 || perIP["1.1.1.1"] != 1 || len(perIP) != 2 {
		t.Errorf("alerts per source = %v, want exactly one each", perIP)
	}
	raw, _ := json.Marshal(lapi.accepted)
	if strings.Contains(string(raw), "hunter2") {
		t.Errorf("password reached CrowdSec: %s", raw)
	}
}
