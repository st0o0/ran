package trap

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

// fxResp is one fully read response.
type fxResp struct {
	status int
	header http.Header
	body   string
}

func fxClient(tlsOn bool) *http.Client {
	tr := &http.Transport{DisableKeepAlives: true}
	if tlsOn {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test client for a self-signed trap
	}
	return &http.Client{Transport: tr, Timeout: 5 * time.Second}
}

func fxDo(t *testing.T, tlsOn bool, addr, method, target string, headers map[string]string, body string) fxResp {
	t.Helper()
	scheme := "http://"
	if tlsOn {
		scheme = "https://"
	}
	req, err := http.NewRequest(method, scheme+addr+target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := fxClient(tlsOn).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return fxResp{status: resp.StatusCode, header: resp.Header, body: string(b)}
}

func startFixtureTrap(t *testing.T, proto string, operator []config.HTTPFixture) (string, *eventSink) {
	t.Helper()
	if proto == "https" {
		return startSensorTrap(t, "https", func(cfg *config.Config, l *slog.Logger, m *metrics.Metrics, lim *Limiter, r Reporter) Trap {
			cfg.HTTPFixtures = operator
			return newHTTPSTrap(t, cfg, r, lim)
		})
	}
	return startSensorTrap(t, "http", func(cfg *config.Config, l *slog.Logger, m *metrics.Metrics, lim *Limiter, r Reporter) Trap {
		cfg.HTTPFixtures = operator
		return NewHTTP(cfg, l, m, lim, r)
	})
}

var builtinWant = []struct {
	path, contentType, bodyPart string
}{
	{"/.git/HEAD", "text/plain", "ref: refs/heads/main"},
	{"/.git/config", "text/plain", "[remote \"origin\"]"},
	{"/.env", "text/plain", "APP_ENV=production"},
	{"/actuator/health", "application/vnd.spring-boot.actuator.v3+json", `"status":"UP"`},
	{"/actuator/env", "application/vnd.spring-boot.actuator.v3+json", "activeProfiles"},
	{"/server-status", "text/html", "Apache Server Status"},
	{"/phpinfo.php", "text/html", "PHP Version 8.3.6"},
	{"/wp-json/", "application/json", "wp/v2"},
	{"/robots.txt", "text/plain", "User-agent: *"},
	{"/sitemap.xml", "application/xml", "<urlset"},
	{"/.well-known/security.txt", "text/plain", "Contact:"},
}

func TestBuiltinHTTPFixtureTableIsValid(t *testing.T) {
	t.Parallel()
	if len(builtinWant) != len(builtinHTTPFixtures) {
		t.Fatalf("test table has %d entries, built-in table %d", len(builtinWant), len(builtinHTTPFixtures))
	}
	// The built-ins must pass the same validation as operator fixtures.
	type entry struct {
		Path    string            `json:"path"`
		Status  int               `json:"status"`
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
	}
	var entries []entry
	for _, fx := range builtinHTTPFixtures {
		entries = append(entries, entry{fx.Path, fx.Status, fx.Headers, fx.Body})
	}
	raw, err := json.Marshal(map[string]any{"fixtures": entries})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.ParseHTTPFixtures("builtin", raw); err != nil {
		t.Fatalf("built-in table is invalid: %v", err)
	}
	ipv4 := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	for _, fx := range builtinHTTPFixtures {
		if fx.Body == "" {
			t.Errorf("%s: empty body", fx.Path)
		}
		if ipv4.MatchString(fx.Body) {
			t.Errorf("%s: body contains an IP address", fx.Path)
		}
		for _, h := range fx.Headers {
			if ipv4.MatchString(h) {
				t.Errorf("%s: header contains an IP address", fx.Path)
			}
		}
	}
}

func TestBuiltinHTTPFixtures(t *testing.T) {
	t.Parallel()
	for _, proto := range []string{"http", "https"} {
		t.Run(proto, func(t *testing.T) {
			t.Parallel()
			addr, _ := startFixtureTrap(t, proto, nil)
			for _, tc := range builtinWant {
				t.Run(tc.path, func(t *testing.T) {
					got := fxDo(t, proto == "https", addr, "GET", tc.path, nil, "")
					if got.status != 200 {
						t.Errorf("status = %d", got.status)
					}
					if ct := got.header.Get("Content-Type"); !strings.HasPrefix(ct, tc.contentType) {
						t.Errorf("content type = %q, want prefix %q", ct, tc.contentType)
					}
					if !strings.Contains(got.body, tc.bodyPart) {
						t.Errorf("body lacks %q: %q", tc.bodyPart, got.body)
					}
					if got.header.Get("Content-Length") != strconv.Itoa(len(got.body)) {
						t.Errorf("content length = %q, body %d", got.header.Get("Content-Length"), len(got.body))
					}
					if got.header.Get("Server") != "Apache/2.4.62" {
						t.Errorf("server = %q", got.header.Get("Server"))
					}
				})
			}
		})
	}
}

func TestBuiltinHTTPFixtureXPoweredBy(t *testing.T) {
	t.Parallel()
	addr, _ := startFixtureTrap(t, "http", nil)
	if got := fxDo(t, false, addr, "GET", "/phpinfo.php", nil, "").header.Get("X-Powered-By"); got != "PHP/8.3.6" {
		t.Errorf("phpinfo X-Powered-By = %q", got)
	}
	if got := fxDo(t, false, addr, "GET", "/actuator/health", nil, "").header.Get("X-Powered-By"); got != "" {
		t.Errorf("actuator X-Powered-By = %q, want none", got)
	}
}

func TestHTTPFixtureNoReflection(t *testing.T) {
	t.Parallel()
	markers := []string{"REFLECT_QUERY", "REFLECT_UA", "REFLECT_COOKIE", "REFLECT_REFERER", "REFLECT_XFF", "REFLECT_AUTH", "REFLECT_HOST", "REFLECT_ORIGIN"}
	hdrs := map[string]string{
		"User-Agent":      "REFLECT_UA",
		"Cookie":          "s=REFLECT_COOKIE",
		"Referer":         "http://REFLECT_REFERER/",
		"X-Forwarded-For": "8.8.8.8 REFLECT_XFF",
		"Origin":          "http://REFLECT_ORIGIN",
		"Accept-Language": "REFLECT_UA",
	}
	for _, proto := range []string{"http", "https"} {
		t.Run(proto, func(t *testing.T) {
			t.Parallel()
			addr, _ := startFixtureTrap(t, proto, []config.HTTPFixture{{Path: "/custom", Status: 200, Body: "static"}})
			paths := []string{"/custom"}
			for _, fx := range builtinHTTPFixtures {
				paths = append(paths, fx.Path)
			}
			for _, p := range paths {
				for _, method := range []string{"GET", "HEAD"} {
					h := map[string]string{"Authorization": "Basic UkVGTEVDVF9BVVRIOng="}
					for k, v := range hdrs {
						h[k] = v
					}
					got := fxDo(t, proto == "https", addr, method, p+"?q=REFLECT_QUERY", h, "")
					all := got.body
					for k, vs := range got.header {
						all += k + ": " + strings.Join(vs, ",") + "\n"
					}
					for _, m := range markers {
						if strings.Contains(all, m) {
							t.Errorf("%s %s reflects %s", method, p, m)
						}
					}
					for _, bad := range []string{"8.8.8.8", "UkVGTEVDVF9BVVRIOng"} {
						if strings.Contains(all, bad) {
							t.Errorf("%s %s reflects %s", method, p, bad)
						}
					}
				}
			}
		})
	}
}

func TestHTTPFixtureScriptPathNotReflected(t *testing.T) {
	t.Parallel()
	addr, _ := startFixtureTrap(t, "http", nil)
	for _, p := range []string{"/robots.txt/<script>alert(1)</script>", "/<script>alert(1)</script>", "/.git/HEAD%3Cscript%3E"} {
		got := fxDo(t, false, addr, "GET", p, nil, "")
		if strings.Contains(got.body, "script") || strings.Contains(got.body, "alert(1)") {
			t.Errorf("%s reflects the path: %q", p, got.body)
		}
	}
	// Matching is exact: a path that only starts like a fixture gets the login page.
	got := fxDo(t, false, addr, "GET", "/robots.txt/x", nil, "")
	if !strings.Contains(got.body, "<form") {
		t.Errorf("non-fixture path did not get the login page: %q", got.body)
	}
}

func TestHTTPFixtureHEAD(t *testing.T) {
	t.Parallel()
	addr, _ := startFixtureTrap(t, "http", []config.HTTPFixture{
		{Path: "/gone", Status: 404, Headers: map[string]string{"Content-Type": "text/plain"}, Body: "not here"},
		{Path: "/empty", Status: 204},
	})
	paths := []string{"/gone"}
	for _, fx := range builtinHTTPFixtures {
		paths = append(paths, fx.Path)
	}
	for _, p := range paths {
		get := fxDo(t, false, addr, "GET", p, nil, "")
		head := fxDo(t, false, addr, "HEAD", p, nil, "")
		if head.status != get.status || head.body != "" {
			t.Errorf("%s: HEAD status %d body %q, GET status %d", p, head.status, head.body, get.status)
		}
		if head.header.Get("Content-Length") != strconv.Itoa(len(get.body)) {
			t.Errorf("%s: HEAD content length = %q, want %d", p, head.header.Get("Content-Length"), len(get.body))
		}
		if head.header.Get("Content-Type") != get.header.Get("Content-Type") {
			t.Errorf("%s: HEAD content type differs", p)
		}
	}
	if got := fxDo(t, false, addr, "GET", "/empty", nil, ""); got.status != 204 || got.body != "" {
		t.Errorf("204 fixture: %d %q", got.status, got.body)
	}
	if got := fxDo(t, false, addr, "HEAD", "/empty", nil, ""); got.status != 204 {
		t.Errorf("204 HEAD: %d", got.status)
	}
}

func TestHTTPOperatorFixtures(t *testing.T) {
	t.Parallel()
	operator := []config.HTTPFixture{
		{Path: "/status", Status: 200, Headers: map[string]string{"Content-Type": "application/json", "X-Frame-Options": "DENY"}, Body: `{"state":"ok"}`},
		{Path: "/robots.txt", Status: 404, Headers: map[string]string{}, Body: "operator wins"},
		{Path: "/", Status: 200, Headers: map[string]string{"Content-Type": "text/html"}, Body: "<p>home</p>"},
		{Path: "/wp-login.php", Status: 200, Headers: map[string]string{}, Body: "fixture login"},
		{Path: "/secret", Status: 403, Headers: map[string]string{"Server": "custom/1.0"}, Body: "denied"},
	}
	for _, proto := range []string{"http", "https"} {
		t.Run(proto, func(t *testing.T) {
			t.Parallel()
			tlsOn := proto == "https"
			addr, _ := startFixtureTrap(t, proto, operator)

			got := fxDo(t, tlsOn, addr, "GET", "/status", nil, "")
			if got.status != 200 || got.body != `{"state":"ok"}` || got.header.Get("Content-Type") != "application/json" || got.header.Get("X-Frame-Options") != "DENY" {
				t.Errorf("/status = %+v", got)
			}
			got = fxDo(t, tlsOn, addr, "GET", "/robots.txt", nil, "")
			if got.status != 404 || got.body != "operator wins" || got.header.Get("Content-Type") != "text/plain; charset=utf-8" {
				t.Errorf("operator does not win over built-in: %+v", got)
			}
			got = fxDo(t, tlsOn, addr, "GET", "/secret", nil, "")
			if got.status != 403 || got.header.Get("Server") != "custom/1.0" {
				t.Errorf("/secret = %+v", got)
			}
			if got = fxDo(t, tlsOn, addr, "GET", "/", nil, ""); got.body != "<p>home</p>" {
				t.Errorf("/ = %+v", got)
			}
			// Built-ins that the operator did not replace stay.
			if got = fxDo(t, tlsOn, addr, "GET", "/sitemap.xml", nil, ""); !strings.Contains(got.body, "<urlset") {
				t.Errorf("built-in lost: %+v", got)
			}
		})
	}
}

// A fixture never takes over POST: form logins on a fixture path are captured and
// answered with the login error page, and other methods keep the login page.
func TestHTTPFixturesDoNotOverridePOSTLogin(t *testing.T) {
	t.Parallel()
	operator := []config.HTTPFixture{{Path: "/wp-login.php", Status: 200, Body: "fixture login"}, {Path: "/admin", Status: 200, Body: "fixture admin"}}
	addr, sink := startFixtureTrap(t, "http", operator)

	if got := fxDo(t, false, addr, "GET", "/wp-login.php", nil, ""); got.body != "fixture login" {
		t.Errorf("GET = %q", got.body)
	}
	form := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	got := fxDo(t, false, addr, "POST", "/wp-login.php", form, "log=admin&pwd=hunter2")
	if !strings.Contains(got.body, "The username or password you entered is incorrect") {
		t.Errorf("POST login did not get the error page: %q", got.body)
	}
	ev := waitAttack(t, sink)
	if ev.Info.AuthAttempts != 1 || ev.Meta["username"] != "admin" {
		t.Errorf("credentials not captured: %+v %v", ev.Info, ev.Meta)
	}

	got = fxDo(t, false, addr, "POST", "/robots.txt", form, "username=a&password=b")
	if !strings.Contains(got.body, "Invalid credentials") {
		t.Errorf("POST on a built-in path: %q", got.body)
	}
	for _, m := range []string{"OPTIONS", "PUT", "DELETE"} {
		got = fxDo(t, false, addr, m, "/robots.txt", nil, "")
		if !strings.Contains(got.body, "<form") || strings.Contains(got.body, "Disallow") {
			t.Errorf("%s on a fixture path: %q", m, got.body)
		}
	}
}

// Matching is exact: case differences and a trailing slash miss the fixture and
// get the login page.
func TestHTTPFixtureMatchIsExact(t *testing.T) {
	t.Parallel()
	addr, _ := startFixtureTrap(t, "http", nil)
	if got := fxDo(t, false, addr, "GET", "/robots.txt", nil, ""); strings.Contains(got.body, "<form") {
		t.Fatalf("/robots.txt did not get the fixture: %q", got.body)
	}
	for _, p := range []string{"/ROBOTS.txt", "/robots.txt/"} {
		got := fxDo(t, false, addr, "GET", p, nil, "")
		if !strings.Contains(got.body, "<form") {
			t.Errorf("%s did not get the login page: %q", p, got.body)
		}
	}
}

func TestHTTPFixtureClassification(t *testing.T) {
	t.Parallel()
	cases := []struct {
		path   string
		attack bool
	}{
		{"/.git/HEAD", true},
		{"/.git/config", true},
		{"/.env", true},
		{"/actuator/health", true},
		{"/actuator/env", true},
		{"/server-status", true},
		{"/phpinfo.php", true},
		{"/wp-json/", false},
		{"/robots.txt", false},
		{"/sitemap.xml", false},
		{"/.well-known/security.txt", false},
	}
	for _, proto := range []string{"http", "https"} {
		for _, tc := range cases {
			t.Run(proto+tc.path, func(t *testing.T) {
				t.Parallel()
				addr, sink := startFixtureTrap(t, proto, nil)
				got := fxDo(t, proto == "https", addr, "GET", tc.path+"?x=1", map[string]string{"User-Agent": "scanner/1"}, "")
				if got.status != 200 {
					t.Fatalf("status = %d", got.status)
				}
				if !tc.attack {
					evs := sink.waitEvents(t, func(e []alert.Event) bool { return hasClass(e, alert.ClassProbe) })
					if len(evs) != 1 || evs[0].Class != alert.ClassProbe {
						t.Fatalf("want a single probe event, got %+v", evs)
					}
					return
				}
				ev := waitAttack(t, sink)
				if ev.Info.Commands != 1 || ev.Meta["path"] != tc.path || ev.Meta["method"] != "GET" || ev.Meta["user_agent"] != "scanner/1" {
					t.Errorf("event = %+v meta = %v", ev.Info, ev.Meta)
				}
				if ev.Info.SourceIP != "127.0.0.1" {
					t.Errorf("source ip = %q", ev.Info.SourceIP)
				}
			})
		}
	}
}

// The request capture rules still apply to a fixture hit: the request line is a
// logged command with the usual fields.
func TestHTTPFixtureHitIsLoggedWithCaptureFields(t *testing.T) {
	SetPasswordLogMode("off")
	buf := &syncBuffer{}
	cfg := httpTestConfig(t)
	tr := NewHTTP(cfg, slog.New(slog.NewJSONHandler(buf, nil)), metrics.New(prometheus.NewRegistry(), "test"), NewLimiter(10, 10), alert.NoopAlerter{})
	ctx := t.Context()
	addr := serveTrap(t, ctx, tr)

	fxDo(t, false, addr, "GET", "/.env?token=secret", map[string]string{"User-Agent": "zgrab/0.x", "Cookie": "session=topsecret"}, "")
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(buf.String(), `"action":"disconnect"`) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	out := buf.String()
	for _, want := range []string{`"action":"command"`, `"path":"/.env"`, `"method":"GET"`, `"user_agent":"zgrab/0.x"`} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %s:\n%s", want, out)
		}
	}
	for _, bad := range []string{"token=secret", "topsecret"} {
		if strings.Contains(out, bad) {
			t.Errorf("log leaks %q", bad)
		}
	}
}

// docker, kubernetes and mcp keep their own handlers; operator fixtures set in the
// shared config do not reach them.
func TestFixturesDoNotAffectOtherHTTPTraps(t *testing.T) {
	t.Parallel()
	operator := []config.HTTPFixture{
		{Path: "/version", Status: 200, Body: "FIXTURE"},
		{Path: "/healthz", Status: 200, Body: "FIXTURE"},
		{Path: "/", Status: 200, Body: "FIXTURE"},
		{Path: "/mcp", Status: 200, Body: "FIXTURE"},
	}
	builders := map[string]trapBuilder{
		"docker": func(c *config.Config, l *slog.Logger, m *metrics.Metrics, lim *Limiter, r Reporter) Trap {
			c.HTTPFixtures = operator
			tr := NewDocker(c, l, m, lim, r)
			if tr.fixtures != nil {
				t.Error("docker has a fixture set")
			}
			return tr
		},
		"kubernetes": func(c *config.Config, l *slog.Logger, m *metrics.Metrics, lim *Limiter, r Reporter) Trap {
			c.HTTPFixtures = operator
			tr := NewKubernetes(c, l, m, lim, r)
			if tr.fixtures != nil {
				t.Error("kubernetes has a fixture set")
			}
			return tr
		},
		"mcp": func(c *config.Config, l *slog.Logger, m *metrics.Metrics, lim *Limiter, r Reporter) Trap {
			c.HTTPFixtures = operator
			tr := NewMCP(c, l, m, lim, r)
			if tr.fixtures != nil {
				t.Error("mcp has a fixture set")
			}
			return tr
		},
	}
	for name, build := range builders {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			addr, _ := startSensorTrap(t, name, build)
			for _, p := range []string{"/robots.txt", "/version", "/healthz", "/", "/mcp"} {
				for _, m := range []string{"GET", "HEAD"} {
					got := fxDo(t, false, addr, m, p, nil, "")
					if strings.Contains(got.body, "FIXTURE") || strings.Contains(got.body, "Disallow") {
						t.Errorf("%s %s %s served a fixture: %q", name, m, p, got.body)
					}
				}
			}
		})
	}
	// Spot checks that the own handlers still answer as before.
	addr, _ := startSensorTrap(t, "docker", builders["docker"])
	if got := fxDo(t, false, addr, "GET", "/version", nil, ""); !strings.Contains(got.body, `"ApiVersion":"1.43"`) {
		t.Errorf("docker /version = %q", got.body)
	}
	addr, _ = startSensorTrap(t, "docker", builders["docker"])
	if got := fxDo(t, false, addr, "GET", "/robots.txt", nil, ""); got.status != 404 {
		t.Errorf("docker /robots.txt status = %d, want 404", got.status)
	}
}
