package trap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestKubernetesRequests(t *testing.T) {
	t.Parallel()
	form := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	cases := []struct {
		name       string
		method     string
		path       string
		headers    map[string]string
		body       string
		status     int
		attack     bool
		wantBody   string
		wantMetaIn []string
	}{
		{name: "version", method: "GET", path: "/version", status: 200, wantBody: `"gitVersion":"v1.29.4"`},
		{name: "healthz", method: "GET", path: "/healthz", status: 200, wantBody: "ok"},
		{name: "readyz", method: "GET", path: "/readyz", status: 200, wantBody: "ok"},
		{name: "api", method: "GET", path: "/api", status: 200, wantBody: `"kind":"APIVersions"`},
		{name: "kubelet pods", method: "GET", path: "/pods", status: 401, wantBody: "Unauthorized"},
		{name: "kubelet runningpods", method: "GET", path: "/runningpods/", status: 401, wantBody: "Unauthorized"},
		{name: "anonymous other path", method: "GET", path: "/api/v1/namespaces", status: 403, wantBody: "system:anonymous"},
		{name: "path is encoded in message", method: "GET", path: "/%22quote", status: 403, wantBody: `\"/\\\"quote\"`},
		{name: "run via form", method: "POST", path: "/run/default/pod/ctr", headers: form, body: "cmd=id", status: 403, attack: true, wantMetaIn: []string{"/run/default/pod/ctr", "cmd=id"}},
		{name: "run via query", method: "POST", path: "/run/default/pod/ctr?cmd=whoami", status: 403, attack: true, wantMetaIn: []string{"cmd=whoami"}},
		{name: "exec", method: "POST", path: "/exec/ns/pod/ctr?command=sh&command=-c&input=1", status: 403, attack: true, wantMetaIn: []string{"cmd=sh -c"}},
		{name: "attach get", method: "GET", path: "/attach/ns/pod/ctr", status: 403, attack: true},
		{name: "run oversized form", method: "POST", path: "/run/a/b/c", headers: form, body: "cmd=" + strings.Repeat("a", 40000), status: 403, attack: true},
		{name: "post elsewhere", method: "POST", path: "/api/v1/namespaces/default/pods", body: `{"kind":"Pod"}`, status: 403, attack: true},
		{name: "delete", method: "DELETE", path: "/api/v1/namespaces/x", status: 403, attack: true},
		{name: "long path", method: "POST", path: "/" + strings.Repeat("p", 2000), status: 403, attack: true},
		{name: "get with body", method: "GET", path: "/version", body: `{"a":1}`, status: 200, attack: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := startKubernetes(t)
			res := stubDo(t, h.addr, tc.method, tc.path, tc.headers, tc.body)
			if res.status != tc.status {
				t.Errorf("status = %d, want %d (%s)", res.status, tc.status, res.body)
			}
			if tc.wantBody != "" && !strings.Contains(res.body, tc.wantBody) {
				t.Errorf("body = %q, want it to contain %q", res.body, tc.wantBody)
			}
			if strings.HasPrefix(res.header.Get("Content-Type"), "application/json") && !json.Valid([]byte(res.body)) {
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
		})
	}
}

func TestKubernetesBearerTokenIsHashedOnly(t *testing.T) {
	t.Parallel()
	const token = "eyJhbGciOiJSUzI1NiJ9.supersecretpayload.sig"
	sum := sha256.Sum256([]byte(token))
	wantHash := hex.EncodeToString(sum[:])[:stubTokenHashLen]

	h := startKubernetes(t)
	res := stubDo(t, h.addr, "GET", "/api/v1/pods", map[string]string{
		"Authorization":   "Bearer " + token,
		"X-Forwarded-For": "8.8.8.8",
	}, "")
	if res.status != 401 {
		t.Errorf("status = %d, want 401 for a rejected token", res.status)
	}
	ev := waitAttack(t, h.sink)
	if ev.Info.AuthAttempts != 1 || ev.Meta["token_hash"] != wantHash {
		t.Errorf("auth = %d, meta = %v, want token_hash %s", ev.Info.AuthAttempts, ev.Meta, wantHash)
	}
	if ev.Info.SourceIP != "127.0.0.1" {
		t.Errorf("alert ip = %q, want the socket peer", ev.Info.SourceIP)
	}
	for k, v := range ev.Meta {
		if strings.Contains(v, "supersecret") || strings.Contains(v, token) || strings.Contains(v, "8.8.8.8") {
			t.Errorf("meta %s=%q leaks the token or a forwarded address", k, v)
		}
	}
	out := h.logs.String()
	if !strings.Contains(out, `"token_hash":"`+wantHash+`"`) || !strings.Contains(out, `"action":"auth_attempt"`) {
		t.Errorf("auth attempt with hash not logged:\n%s", out)
	}
	if strings.Contains(out, "supersecret") || strings.Contains(out, token) {
		t.Errorf("log leaks the token:\n%s", out)
	}
}

func TestKubernetesEmptyOrOtherAuthIsNoToken(t *testing.T) {
	t.Parallel()
	for name, hdr := range map[string]string{"empty bearer": "Bearer ", "basic": "Basic YTpi", "bare": "Bearer"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := startKubernetes(t)
			stubDo(t, h.addr, "GET", "/version", map[string]string{"Authorization": hdr}, "")
			h.waitClass(t, false)
		})
	}
}

func TestKubernetesExecLogsCommand(t *testing.T) {
	t.Parallel()
	h := startKubernetes(t)
	stubDo(t, h.addr, "POST", "/run/default/pod/ctr", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, "cmd=id")
	ev := waitAttack(t, h.sink)
	if ev.Info.Commands != 1 {
		t.Errorf("commands = %d, want 1", ev.Info.Commands)
	}
	if out := h.logs.String(); !strings.Contains(out, `"action":"command"`) || !strings.Contains(out, "cmd=id") {
		t.Errorf("command not logged:\n%s", out)
	}
}

func TestKubernetesStopClosesConnections(t *testing.T) {
	t.Parallel()
	h := startKubernetes(t)
	assertStopClosesConnections(t, h, "GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
}

func TestKubeCommandBounded(t *testing.T) {
	t.Parallel()
	h := startKubernetes(t)
	q := strings.Repeat("&cmd=abcdefghij", 500)
	stubDo(t, h.addr, "POST", "/run/a/b/c?"+q[1:], nil, "")
	ev := waitAttack(t, h.sink)
	if len(ev.Meta["command"]) > maxHTTPValue {
		t.Errorf("command meta is %d bytes", len(ev.Meta["command"]))
	}
}
