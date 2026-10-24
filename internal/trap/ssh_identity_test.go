package trap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/st0o0/ran/internal/alert"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/metrics"
	gossh "golang.org/x/crypto/ssh"
)

// Published HASSH example from github.com/salesforce/hassh (README, "Example 1"):
// Cyberduck 6.7.1 (28683) has HASSH 8a8ae540028bf433cd68356c1b9e8d5b.
const (
	cyberduckKex  = "curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group14-sha256,diffie-hellman-group15-sha512,diffie-hellman-group16-sha512,diffie-hellman-group17-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256@ssh.com,diffie-hellman-group15-sha256,diffie-hellman-group15-sha256@ssh.com,diffie-hellman-group15-sha384@ssh.com,diffie-hellman-group16-sha256,diffie-hellman-group16-sha384@ssh.com,diffie-hellman-group16-sha512@ssh.com,diffie-hellman-group18-sha512@ssh.com"
	cyberduckEnc  = "aes128-cbc,aes128-ctr,aes192-cbc,aes192-ctr,aes256-cbc,aes256-ctr,blowfish-cbc,blowfish-ctr,cast128-cbc,cast128-ctr,idea-cbc,idea-ctr,serpent128-cbc,serpent128-ctr,serpent192-cbc,serpent192-ctr,serpent256-cbc,serpent256-ctr,3des-cbc,3des-ctr,twofish128-cbc,twofish128-ctr,twofish192-cbc,twofish192-ctr,twofish256-cbc,twofish256-ctr,twofish-cbc,arcfour,arcfour128,arcfour256"
	cyberduckMAC  = "hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96,hmac-sha2-256,hmac-sha2-512"
	cyberduckComp = "zlib@openssh.com,zlib,none"
	cyberduckHash = "8a8ae540028bf433cd68356c1b9e8d5b"
)

func buildKexInitStream(version string, lists [8]string, pad int) []byte {
	var payload bytes.Buffer
	payload.WriteByte(sshMsgKexInit)
	payload.Write(make([]byte, 16))
	for _, l := range lists {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(l)))
		payload.Write(n[:])
		payload.WriteString(l)
	}
	payload.WriteByte(0)
	payload.Write(make([]byte, 4))
	var out bytes.Buffer
	out.WriteString(version + "\r\n")
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(1+payload.Len()+pad))
	out.Write(n[:])
	out.WriteByte(byte(pad))
	out.Write(payload.Bytes())
	out.Write(make([]byte, pad))
	return out.Bytes()
}

func TestHasshPublishedVector(t *testing.T) {
	t.Parallel()
	if got := hasshOf(cyberduckKex, cyberduckEnc, cyberduckMAC, cyberduckComp); got != cyberduckHash {
		t.Fatalf("hassh = %s, want %s", got, cyberduckHash)
	}
	lists := [8]string{cyberduckKex, "ssh-ed25519", cyberduckEnc, "other-enc", cyberduckMAC, "other-mac", cyberduckComp, "other-comp"}
	stream := buildKexInitStream("SSH-2.0-Cyberduck/6.7.1.28683", lists, 6)
	if got, done := scanKexInit(stream); !done || got != cyberduckHash {
		t.Fatalf("scanKexInit = %q, %v; want %s, true", got, done, cyberduckHash)
	}
	for i := 0; i < len(stream); i++ {
		if got, done := scanKexInit(stream[:i]); done || got != "" {
			t.Fatalf("prefix of %d bytes = %q, %v; want need-more", i, got, done)
		}
	}
	pre := append([]byte("banner line\r\n"), stream...)
	if got, _ := scanKexInit(pre); got != cyberduckHash {
		t.Errorf("with a pre-version line: %q", got)
	}
}

func TestScanKexInitRejectsGarbage(t *testing.T) {
	t.Parallel()
	valid := buildKexInitStream("SSH-2.0-x", [8]string{"a", "b", "c", "d", "e", "f", "g", "h"}, 4)
	huge := append([]byte("SSH-2.0-x\r\n"), 0xff, 0xff, 0xff, 0xff, 4, sshMsgKexInit)
	notKex := append([]byte("SSH-2.0-x\r\n"), 0, 0, 0, 12, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	badList := append([]byte(nil), valid...)
	badList[len("SSH-2.0-x\r\n")+4+1+1+16+3] = 0xff // first name-list length
	for name, in := range map[string][]byte{"huge length": huge, "not kexinit": notKex, "bad list": badList} {
		if got, done := scanKexInit(in); got != "" || !done {
			t.Errorf("%s: %q, %v; want empty, done", name, got, done)
		}
	}
}

func TestSanitizeClientVersion(t *testing.T) {
	t.Parallel()
	if got := sanitizeClientVersion("SSH-2.0-libssh_0.9.6"); got != "SSH-2.0-libssh_0.9.6" {
		t.Errorf("got %q", got)
	}
	if got := sanitizeClientVersion(strings.Repeat("A", 300)); len(got) != maxSSHClientVersion {
		t.Errorf("len = %d, want %d", len(got), maxSSHClientVersion)
	}
	if got := sanitizeClientVersion("SSH-2.0-a\x00\x1b[31m\xffz"); got != "SSH-2.0-a[31mz" {
		t.Errorf("control bytes kept: %q", got)
	}
}

type sshIDTrap struct {
	addr string
	rec  *recordingAlerter
	logs *syncBuffer
	reg  *prometheus.Registry
}

func startSSHIdentityTrap(t *testing.T, retries int, delay time.Duration) sshIDTrap {
	t.Helper()
	cfg := testConfig(t)
	cfg.MaxAuthRetries = retries
	cfg.AuthDelay = delay
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	rec := &recordingAlerter{}
	logs := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, nil))
	sshTrap, err := NewSSH(cfg, logger, m, NewLimiter(cfg.MaxSessions, cfg.MaxPerIP), rec)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return sshIDTrap{addr: serveTrap(t, ctx, sshTrap), rec: rec, logs: logs, reg: reg}
}

func newSigners(t *testing.T, n int) []gossh.Signer {
	t.Helper()
	var out []gossh.Signer
	for i := 0; i < n; i++ {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		s, err := gossh.NewSignerFromKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

func dialSSH(addr, user string, methods ...gossh.AuthMethod) {
	c, err := gossh.Dial("tcp", addr, &gossh.ClientConfig{
		User:            user,
		Auth:            methods,
		ClientVersion:   "SSH-2.0-libssh_0.9.6",
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	})
	if err == nil {
		c.Close()
	}
}

func interactive(answer string) gossh.AuthMethod {
	return gossh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
		out := make([]string, len(questions))
		for i := range out {
			out[i] = answer
		}
		return out, nil
	})
}

// Not parallel: it switches the package-level password log mode.
func TestSSHIdentityCapture(t *testing.T) {
	signers := newSigners(t, 1)
	fp := gossh.FingerprintSHA256(signers[0].PublicKey())
	cases := []struct {
		name    string
		methods []gossh.AuthMethod
		attempt int
		method  string
		secret  string
		keyFP   string
	}{
		{"key only", []gossh.AuthMethod{gossh.PublicKeys(signers...)}, 1, "publickey", "", fp},
		{"interactive", []gossh.AuthMethod{interactive("hunter2")}, 1, "keyboard-interactive", "hunter2", ""},
		{"password", []gossh.AuthMethod{gossh.Password("hunter2")}, 1, "", "hunter2", ""},
		{"mixed", []gossh.AuthMethod{gossh.PublicKeys(signers...), interactive("hunter2"), gossh.Password("hunter2")}, 3, "", "hunter2", fp},
	}
	SetPasswordLogMode("on")
	defer SetPasswordLogMode("off")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := startSSHIdentityTrap(t, 6, 0)
			dialSSH(tr.addr, "root", tc.methods...)
			waitUntil(t, func() bool { return len(tr.rec.snapshot()) >= tc.attempt })
			alerts := tr.rec.snapshot()
			if len(alerts) != tc.attempt {
				t.Fatalf("alerts = %d, want %d", len(alerts), tc.attempt)
			}
			for _, a := range alerts {
				if a.Meta["username"] != "root" || a.Meta["client_version"] != "SSH-2.0-libssh_0.9.6" {
					t.Errorf("meta = %v", a.Meta)
				}
				if len(a.Meta["hassh"]) != 32 {
					t.Errorf("hassh meta = %q", a.Meta["hassh"])
				}
				if m := a.Meta["method"]; m == "keyboard-interactive" || m == "publickey" {
					if _, ok := a.Meta["password"]; ok {
						t.Errorf("password in %s meta: %v", m, a.Meta)
					}
				}
			}
			last := alerts[len(alerts)-1]
			if tc.method != "" && last.Meta["method"] != tc.method {
				t.Errorf("method = %q, want %q", last.Meta["method"], tc.method)
			}
			if tc.keyFP != "" {
				found := false
				for _, a := range alerts {
					if a.Meta["fingerprint"] == tc.keyFP && a.Meta["key_type"] == "ssh-ed25519" {
						found = true
					}
				}
				if !found {
					t.Errorf("no alert with fingerprint %s: %v", tc.keyFP, alerts)
				}
			}
			waitUntil(t, func() bool { return strings.Count(tr.logs.String(), `"action":"auth_attempt"`) >= tc.attempt })
			out := tr.logs.String()
			for _, want := range []string{`"client_version":"SSH-2.0-libssh_0.9.6"`, `"hassh":"`} {
				if !strings.Contains(out, want) {
					t.Errorf("log lacks %s:\n%s", want, out)
				}
			}
			if tc.keyFP != "" && !strings.Contains(out, tc.keyFP) {
				t.Errorf("log lacks fingerprint")
			}
			if tc.secret != "" && !strings.Contains(out, `"password":"`+tc.secret+`"`) {
				t.Errorf("log lacks password with mode on:\n%s", out)
			}
			if got := counterSum(t, tr.reg, "ran_credentials_captured_total", "protocol", "ssh"); got != float64(tc.attempt) {
				t.Errorf("credentials metric = %v, want %d", got, tc.attempt)
			}
		})
	}
}

// Not parallel: it reads the package-level password log mode.
func TestSSHInteractivePasswordOffByDefault(t *testing.T) {
	SetPasswordLogMode("off")
	tr := startSSHIdentityTrap(t, 3, 0)
	dialSSH(tr.addr, "root", interactive("hunter2"))
	waitUntil(t, func() bool { return strings.Contains(tr.logs.String(), `"action":"auth_attempt"`) })
	if strings.Contains(tr.logs.String(), "hunter2") {
		t.Errorf("password logged with mode off:\n%s", tr.logs.String())
	}
	for _, a := range tr.rec.snapshot() {
		for k, v := range a.Meta {
			if strings.Contains(v, "hunter2") {
				t.Errorf("secret in meta %s", k)
			}
		}
	}
}

func TestSSHKeyAttemptLimits(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ retries, offered, want int }{{3, 5, 3}, {0, 9, 9}} {
		t.Run(fmt.Sprintf("retries_%d", tc.retries), func(t *testing.T) {
			t.Parallel()
			tr := startSSHIdentityTrap(t, tc.retries, 0)
			dialSSH(tr.addr, "root", gossh.PublicKeys(newSigners(t, tc.offered)...))
			waitUntil(t, func() bool { return len(tr.rec.snapshot()) >= tc.want })
			time.Sleep(100 * time.Millisecond)
			if got := len(tr.rec.snapshot()); got != tc.want {
				t.Errorf("attempts = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestSSHKeyAttemptDelayGrows(t *testing.T) {
	t.Parallel()
	const delay = 40 * time.Millisecond
	tr := startSSHIdentityTrap(t, 3, delay)
	start := time.Now()
	dialSSH(tr.addr, "root", gossh.PublicKeys(newSigners(t, 3)...))
	waitUntil(t, func() bool { return len(tr.rec.snapshot()) >= 3 })
	// Delays of 1x, 2x and 4x the base are applied to the three rejections.
	if elapsed := time.Since(start); elapsed < 7*delay {
		t.Errorf("elapsed %v, want at least %v", elapsed, 7*delay)
	}
}

// dialRaw connects, optionally sends a PROXY header and runs the SSH client
// handshake over the raw connection, so a test can hang up at any point.
func dialRaw(t *testing.T, addr, proxyIP, user string, methods ...gossh.AuthMethod) (net.Conn, error) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if proxyIP != "" {
		fmt.Fprintf(conn, "PROXY TCP4 %s 127.0.0.1 40000 22\r\n", proxyIP)
	}
	_, chans, reqs, err := gossh.NewClientConn(conn, addr, &gossh.ClientConfig{
		User:            user,
		Auth:            methods,
		ClientVersion:   "SSH-2.0-libssh_0.9.6",
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		conn.Close()
		return nil, err
	}
	go gossh.DiscardRequests(reqs)
	go func() {
		for nc := range chans {
			_ = nc.Reject(gossh.Prohibited, "")
		}
	}()
	return conn, nil
}

// A failed keyboard-interactive exchange (wrong number of answers, or the
// client hanging up mid-prompt) is still an attempt: logged, counted, alerted.
func TestSSHInteractiveFailedExchangeIsRecorded(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		answer func(conn *net.Conn) gossh.AuthMethod
	}{
		{"wrong answer count", func(*net.Conn) gossh.AuthMethod {
			return gossh.KeyboardInteractive(func(_, _ string, _ []string, _ []bool) ([]string, error) {
				return []string{"a", "b", "c"}, nil
			})
		}},
		{"hang up mid prompt", func(conn *net.Conn) gossh.AuthMethod {
			return gossh.KeyboardInteractive(func(_, _ string, _ []string, _ []bool) ([]string, error) {
				_ = (*conn).Close()
				return nil, errors.New("hang up")
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tr := startSSHIdentityTrap(t, 6, 0)
			var conn net.Conn
			raw, err := net.DialTimeout("tcp", tr.addr, 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			conn = raw
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			_, _, _, err = gossh.NewClientConn(conn, tr.addr, &gossh.ClientConfig{
				User:            "root",
				Auth:            []gossh.AuthMethod{tc.answer(&conn)},
				ClientVersion:   "SSH-2.0-libssh_0.9.6",
				HostKeyCallback: gossh.InsecureIgnoreHostKey(),
			})
			if err == nil {
				t.Fatal("handshake unexpectedly succeeded")
			}
			conn.Close()
			waitUntil(t, func() bool { return len(tr.rec.snapshot()) >= 1 })
			alerts := tr.rec.snapshot()
			if m := alerts[0].Meta; m["method"] != "keyboard-interactive" || m["username"] != "root" {
				t.Errorf("meta = %v", m)
			}
			if _, ok := alerts[0].Meta["password"]; ok {
				t.Errorf("password in meta: %v", alerts[0].Meta)
			}
			waitUntil(t, func() bool { return strings.Contains(tr.logs.String(), `"action":"auth_attempt"`) })
			if got := counterSum(t, tr.reg, "ran_credentials_captured_total", "protocol", "ssh"); got != 1 {
				t.Errorf("credentials metric = %v, want 1", got)
			}
		})
	}
}

func TestSSHLogBoundsUsername(t *testing.T) {
	SetPasswordLogMode("off")
	tr := startSSHIdentityTrap(t, 3, 0)
	user := "ro\x1b[31mot" + strings.Repeat("x", 400)
	dialSSH(tr.addr, user, gossh.Password("pw"))
	waitUntil(t, func() bool { return strings.Contains(tr.logs.String(), `"action":"auth_attempt"`) })
	out := tr.logs.String()
	if strings.Contains(out, `\u001b`) || strings.Contains(out, strings.Repeat("x", 300)) {
		t.Errorf("username not bounded:\n%s", out)
	}
	if !strings.Contains(out, `"username":"ro [31mot`) {
		t.Errorf("control character not replaced:\n%s", out)
	}
	dialSSH(tr.addr, "root", gossh.Password("pw"))
	waitUntil(t, func() bool { return strings.Contains(tr.logs.String(), `"username":"root"`) })
}

// Not parallel: it switches the package-level password log mode.
// With password logging on, no password value or key may reach CrowdSec on any
// auth path, and no sensor meta key is lost to the key cap.
func TestSSHNoPasswordReachesCrowdSec(t *testing.T) {
	SetPasswordLogMode("on")
	defer SetPasswordLogMode("off")
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

	cfg := testConfig(t)
	cfg.ProxyProtocol = true
	cfg.MaxAuthRetries = 6
	tr, err := NewSSH(cfg, logger, m, NewLimiter(cfg.MaxSessions, cfg.MaxPerIP), sensor)
	if err != nil {
		t.Fatal(err)
	}
	addr := serveTrap(t, ctx, tr)

	signers := newSigners(t, 1)
	methods := []gossh.AuthMethod{gossh.PublicKeys(signers...), interactive("s3cret-int"), gossh.Password("s3cret-pw")}
	conn, _ := dialRaw(t, addr, "8.8.8.8", "root", methods...)
	if conn != nil {
		conn.Close()
	}
	waitFor(t, func() bool { return lapi.acceptedCount() >= 1 })
	time.Sleep(300 * time.Millisecond)

	lapi.mu.Lock()
	defer lapi.mu.Unlock()
	raw, err := json.Marshal(lapi.accepted)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"s3cret-int", "s3cret-pw", `"key":"password"`} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("%q reached CrowdSec: %s", secret, raw)
		}
	}
	for _, batch := range lapi.accepted {
		for _, a := range batch {
			events, _ := a["events"].([]any)
			for _, e := range events {
				ev, _ := e.(map[string]any)
				rawMeta, _ := ev["meta"].([]any)
				meta := map[string]string{}
				for _, kv := range rawMeta {
					p, _ := kv.(map[string]any)
					k, _ := p["key"].(string)
					v, _ := p["value"].(string)
					meta[k] = v
				}
				if len(meta) > 32 {
					t.Errorf("%d meta keys, cap is 32", len(meta))
				}
				// Sensor keys survive next to the SSH keys.
				for _, k := range []string{"class", "protocol", "username", "client_version", "hassh"} {
					if meta[k] == "" {
						t.Errorf("meta lacks %s: %v", k, meta)
					}
				}
			}
		}
	}
}

// The meta of a key attempt (the widest SSH meta) plus the sensor keys must fit
// within the CrowdSec meta key cap, so no sensor key is dropped.
func TestSSHAlertMetaFitsKeyCap(t *testing.T) {
	t.Parallel()
	tr := startSSHIdentityTrap(t, 3, 0)
	dialSSH(tr.addr, "root", gossh.PublicKeys(newSigners(t, 1)...))
	waitUntil(t, func() bool { return len(tr.rec.snapshot()) >= 1 })
	meta := tr.rec.snapshot()[0].Meta
	want := []string{"username", "method", "client_version", "hassh", "key_type", "fingerprint"}
	for _, k := range want {
		if meta[k] == "" {
			t.Errorf("meta lacks %s: %v", k, meta)
		}
	}
	const sensorKeys = 6 // class, protocol, dest_port, auth_attempts, commands, payload_bytes
	if got := len(meta) + sensorKeys; got > 32 {
		t.Errorf("%d meta keys with sensor keys, cap is 32", got)
	}
}
