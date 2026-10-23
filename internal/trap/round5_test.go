package trap

import (
	"bufio"
	"context"
	"fmt"
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
	"github.com/st0o0/ran/internal/metrics"
)

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for condition")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestElasticsearchCommandOmitsQueryAndBody(t *testing.T) {
	t.Parallel()
	cfg, _ := esTestConfig(t)
	m := metrics.New(prometheus.NewRegistry(), "test")
	rec := &recordingAlerter{}
	buf := &syncBuffer{}
	tr := NewElasticsearch(cfg, slog.New(slog.NewTextHandler(buf, nil)), m, NewLimiter(cfg.MaxSessions, cfg.MaxPerIP), rec)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	addr := serveTrap(t, ctx, tr)

	req, _ := http.NewRequest(http.MethodPost, "http://"+addr+"/idx/_search?api_key=QUERYSECRET", strings.NewReader(`{"password":"BODYSECRET"}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	waitUntil(t, func() bool { return len(rec.snapshot()) > 0 })
	for _, a := range rec.snapshot() {
		if got := a.Meta["command"]; got != "POST /idx/_search" {
			t.Errorf("alert command = %q, want method and path only", got)
		}
		for k, v := range a.Meta {
			if strings.Contains(v, "QUERYSECRET") || strings.Contains(v, "BODYSECRET") {
				t.Errorf("meta %q leaks a secret: %q", k, v)
			}
		}
	}
	if out := buf.String(); strings.Contains(out, "QUERYSECRET") || strings.Contains(out, "BODYSECRET") {
		t.Errorf("log leaks a secret: %s", out)
	}
}

func TestHTTPProxyTargetDropsQueryAndUserinfo(t *testing.T) {
	t.Parallel()
	cfg, _ := proxyTestConfig(t)
	m := metrics.New(prometheus.NewRegistry(), "test")
	rec := &recordingAlerter{}
	buf := &syncBuffer{}
	tr := NewHTTPProxy(cfg, slog.New(slog.NewTextHandler(buf, nil)), m, NewLimiter(cfg.MaxSessions, cfg.MaxPerIP), rec)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	addr := serveTrap(t, ctx, tr)

	for _, raw := range []string{
		"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
		"GET http://user:PWSECRET@example.com/path?token=QSECRET#frag HTTP/1.1\r\nHost: example.com\r\n\r\n",
	} {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = conn.Write([]byte(raw))
		_, _ = bufio.NewReader(conn).ReadString('\n')
		conn.Close()
	}

	waitUntil(t, func() bool { return len(rec.snapshot()) >= 2 })
	for _, a := range rec.snapshot() {
		for _, v := range a.Meta {
			if strings.Contains(v, "SECRET") {
				t.Errorf("meta leaks a secret: %q", v)
			}
		}
		if !strings.Contains(a.Meta["command"], "example.com") {
			t.Errorf("host missing from command %q", a.Meta["command"])
		}
	}
	if out := buf.String(); strings.Contains(out, "PWSECRET") || strings.Contains(out, "QSECRET") {
		t.Errorf("log leaks a secret: %s", out)
	}
}

func TestSanitizeProxyTarget(t *testing.T) {
	for in, want := range map[string]string{
		"example.com:443":                  "example.com:443",
		"u:p@example.com:443":              "example.com:443",
		"example.com:443?x=1":              "example.com:443",
		"u:p@example.com:443/a/b?x=1#frag": "example.com:443/a/b",
	} {
		if got := sanitizeProxyTarget(in); got != want {
			t.Errorf("sanitizeProxyTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRedisAuthUsernameIsNotPassword(t *testing.T) {
	t.Parallel()
	cfg := testRedisConfig("127.0.0.1:0")
	m := metrics.New(prometheus.NewRegistry(), "test")
	rec := &recordingAlerter{}
	tr := NewRedis(cfg, quietLogger(), m, NewLimiter(cfg.MaxSessions, cfg.MaxPerIP), rec)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	addr := serveTrap(t, ctx, tr)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(conn, "AUTH alice hunter2\r\n")
	if _, err := bufio.NewReader(conn).ReadString('\n'); err != nil {
		t.Fatal(err)
	}

	waitUntil(t, func() bool { return len(rec.snapshot()) > 0 })
	a := rec.snapshot()[0]
	if a.Meta["username"] != "alice" {
		t.Errorf("meta username = %q, want alice", a.Meta["username"])
	}
	if _, ok := a.Meta["password"]; ok {
		t.Error("password must not be in alert meta")
	}
}

func TestRedactCommandACLAndConfig(t *testing.T) {
	old := passwordMode.Load()
	defer passwordMode.Store(old)
	for _, c := range []struct{ line, secret string }{
		{"ACL SETUSER alice on >hunter2 ~* +@all", "hunter2"},
		{"acl setuser bob #5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", "5e884898"},
		{"CONFIG SET masterauth hunter2", "hunter2"},
		{"CONFIG SET masteruser rootuser", "rootuser"},
		{"CONFIG SET requirepass hunter2", "hunter2"},
	} {
		for _, mode := range []string{"off", "mask"} {
			SetPasswordLogMode(mode)
			got := redactCommand(c.line)
			if strings.Contains(got, c.secret) {
				t.Errorf("mode %s: %q leaks %q: %q", mode, c.line, c.secret, got)
			}
		}
	}
	SetPasswordLogMode("off")
	if got := redactCommand("ACL SETUSER alice on >hunter2"); got != "ACL SETUSER alice" {
		t.Errorf("got %q, want the user name kept", got)
	}
	for _, line := range []string{"ACL LIST", "ACL SETUSER alice", "ACL WHOAMI"} {
		if got := redactCommand(line); got != line {
			t.Errorf("redactCommand(%q) = %q, want unchanged", line, got)
		}
	}
}

func TestSSHHostKeyWarnings(t *testing.T) {
	// Missing file in a writable directory: quiet first start.
	dir := t.TempDir()
	buf := &syncBuffer{}
	if _, err := loadOrGenerateHostKey(filepath.Join(dir, "key"), slog.New(slog.NewTextHandler(buf, nil))); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "level=WARN") {
		t.Errorf("first start must not warn: %s", buf.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "key")); err != nil {
		t.Errorf("key not persisted: %v", err)
	}

	// Unwritable location: warn with the chown remedy.
	buf = &syncBuffer{}
	if _, err := loadOrGenerateHostKey(filepath.Join(dir, "missing", "key"), slog.New(slog.NewTextHandler(buf, nil))); err != nil {
		t.Fatal(err)
	}
	if out := buf.String(); !strings.Contains(out, "cannot persist ssh host key") || !strings.Contains(out, "65532") {
		t.Errorf("missing write warning with remedy: %s", out)
	}

	// Unreadable (a directory): warn about the read as well.
	buf = &syncBuffer{}
	if _, err := loadOrGenerateHostKey(dir, slog.New(slog.NewTextHandler(buf, nil))); err != nil {
		t.Fatal(err)
	}
	if out := buf.String(); !strings.Contains(out, "cannot read ssh host key") {
		t.Errorf("missing read warning: %s", out)
	}

	// Corrupt content: warn, then regenerate.
	bad := filepath.Join(dir, "bad")
	if err := os.WriteFile(bad, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	buf = &syncBuffer{}
	if _, err := loadOrGenerateHostKey(bad, slog.New(slog.NewTextHandler(buf, nil))); err != nil {
		t.Fatal(err)
	}
	if out := buf.String(); !strings.Contains(out, "unreadable") {
		t.Errorf("missing corrupt key warning: %s", out)
	}
}

func TestStartAfterStopClosesReady(t *testing.T) {
	tr := newLifecycleTelnet(5 * time.Second)
	if err := tr.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- tr.Start(context.Background()) }()
	select {
	case <-tr.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("Ready stayed open after Start on a stopped trap")
	}
	if err := <-done; err != nil {
		t.Errorf("Start = %v", err)
	}
}

func TestLogRejectedIsRateLimited(t *testing.T) {
	old := rejectLog
	now := time.Unix(1000, 0)
	rejectLog = newRejectLimiter(func() time.Time { return now })
	defer func() { rejectLog = old }()

	buf := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(buf, nil))
	m := metrics.New(prometheus.NewRegistry(), "test")

	for i := 0; i < 5; i++ {
		LogRejected(logger, m, "ssh", alert.TransportTCP, 22, "8.8.8.8", "rate_limit")
	}
	for i := 0; i < 3; i++ {
		LogRejected(logger, m, "dns", alert.TransportUDP, 53, "8.8.8.8", "rate_limit")
	}
	if n := strings.Count(buf.String(), "connection rejected"); n != 2 {
		t.Errorf("warnings = %d, want 1 per protocol (2)", n)
	}
	if got := rejectedCount(t, m, "ssh"); got != 5 {
		t.Errorf("ssh rejected metric = %v, want 5 (unaffected)", got)
	}
	if got := rejectedCount(t, m, "dns"); got != 3 {
		t.Errorf("dns rejected metric = %v, want 3", got)
	}

	now = now.Add(rejectLogInterval + time.Second)
	LogRejected(logger, m, "ssh", alert.TransportTCP, 22, "8.8.8.8", "rate_limit")
	out := buf.String()
	if n := strings.Count(out, "connection rejected"); n != 3 {
		t.Errorf("warnings after the interval = %d, want 3", n)
	}
	if !strings.Contains(out, "suppressed=4") {
		t.Errorf("suppressed count missing: %s", out)
	}
}
