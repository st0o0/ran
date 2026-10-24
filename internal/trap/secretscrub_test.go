package trap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

func TestScrubSecrets(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, in, secret string }{
		{"authorization header", `curl -H 'Authorization: Bearer abc123xyz' http://x`, "abc123xyz"},
		{"authorization lower", `curl -H "authorization: token ghp_abc123"`, "ghp_abc123"},
		{"proxy authorization", `Proxy-Authorization: Basic dXNlcjpwYXNz`, "dXNlcjpwYXNz"},
		{"bearer alone", `run --header Bearer abc123xyz`, "abc123xyz"},
		{"cookie", `curl -H 'Cookie: sid=abc123; other=def456'`, "def456"},
		{"env assignment", `AWS_SECRET=x9y8z7 run.sh`, "x9y8z7"},
		{"env assignment quoted", `export DB_PASSWORD="p w d1" && run`, "p w d1"},
		{"token assignment", `GITHUB_TOKEN=ghp_abc123 git push`, "ghp_abc123"},
		{"api key assignment", `API_KEY=k123 x`, "k123"},
		{"mysql pwd", `MYSQL_PWD=pw123 mysql`, "pw123"},
		{"json style", `{"password":"pw123","user":"root"}`, "pw123"},
		{"flag with value", `mysql --password pw123 -u root`, "pw123"},
		{"flag with equals", `mysql --password=pw123 -u root`, "pw123"},
		{"url userinfo", `git clone https://bob:pw123@host/repo`, "pw123"},
		{"private key", `PRIVATE_KEY=abcdef run`, "abcdef"},
		{"session", `SESSION_ID=abc999 run`, "abc999"},
		{"jwt", `JWT=eyJhbGciOi run`, "eyJhbGciOi"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := scrubSecrets(tc.in)
			if strings.Contains(got, tc.secret) {
				t.Errorf("scrubSecrets(%q) = %q, still holds %q", tc.in, got, tc.secret)
			}
			if !strings.Contains(got, "***") {
				t.Errorf("scrubSecrets(%q) = %q, no marker", tc.in, got)
			}
			if again := scrubSecrets(got); again != got {
				t.Errorf("not idempotent: %q -> %q", got, again)
			}
		})
	}
	// Text without credentials is unchanged.
	for _, in := range []string{"cat /etc/passwd", "tools/call read_file path=/etc/hosts", "id", "ls -la /tmp cwd=/"} {
		if got := scrubSecrets(in); got != in {
			t.Errorf("scrubSecrets(%q) = %q, want it unchanged", in, got)
		}
	}
}

func TestLogScrubFollowsPasswordMode(t *testing.T) {
	defer SetPasswordLogMode("off")
	in := "AWS_SECRET=x9y8z7 run.sh"
	SetPasswordLogMode("off")
	if got := logScrubSecrets(in); strings.Contains(got, "x9y8z7") {
		t.Errorf("off mode: %q", got)
	}
	SetPasswordLogMode("on")
	if got := logScrubSecrets(in); got != in {
		t.Errorf("on mode: %q, want unchanged", got)
	}
	// The meta text is scrubbed in every mode.
	if got := metaCommandText(in); strings.Contains(got, "x9y8z7") {
		t.Errorf("meta in on mode: %q", got)
	}
}

func TestMCPSecretArgKeys(t *testing.T) {
	t.Parallel()
	keys := []string{
		"password", "passwd", "pwd", "passphrase", "secret", "token", "api_key", "api-key", "apikey",
		"access_key", "auth", "authorization", "bearer", "cookie", "session", "jwt", "credential", "private_key",
		"DB_PASSWORD", "X-Auth-Token", "MySecretValue", "Cookie",
	}
	for _, k := range keys {
		t.Run(k, func(t *testing.T) {
			t.Parallel()
			body, _ := json.Marshal(map[string]any{
				"jsonrpc": "2.0", "id": 1, "method": "tools/call",
				"params": map[string]any{"name": "login", "arguments": map[string]any{k: "zz-secret-value-9", "user": "root"}},
			})
			h := startMCP(t)
			mcpPost(t, h, string(body), nil)
			ev := waitAttack(t, h.sink)
			if !strings.Contains(ev.Meta["command"], k+"=***") || !strings.Contains(ev.Meta["command"], "user=root") {
				t.Errorf("command = %q", ev.Meta["command"])
			}
			if strings.Contains(ev.Meta["command"], "zz-secret-value-9") || strings.Contains(h.logs.String(), "zz-secret-value-9") {
				t.Error("secret value recorded")
			}
		})
	}
}

func TestMCPSecretsInsideCommandStrings(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, command string
		secrets       []string
	}{
		{"bearer header", `curl -H 'Authorization: Bearer abcdef123' http://x`, []string{"abcdef123"}},
		{"env prefix", `AWS_SECRET=awsval99 run.sh`, []string{"awsval99"}},
		{"cookie", `curl -H 'Cookie: sid=cookieval77'`, []string{"cookieval77"}},
		{"url", `git clone https://u:urlpw55@h/r`, []string{"urlpw55"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body, _ := json.Marshal(map[string]any{
				"jsonrpc": "2.0", "id": 1, "method": "tools/call",
				"params": map[string]any{"name": "run_command", "arguments": map[string]any{"command": tc.command}},
			})
			h := startMCP(t)
			mcpPost(t, h, string(body), nil)
			ev := waitAttack(t, h.sink)
			if !strings.Contains(ev.Meta["command"], "tools/call run_command command=") {
				t.Errorf("command = %q", ev.Meta["command"])
			}
			for _, s := range tc.secrets {
				if strings.Contains(ev.Meta["command"], s) {
					t.Errorf("meta command holds %q: %q", s, ev.Meta["command"])
				}
				if strings.Contains(h.logs.String(), s) {
					t.Errorf("log holds %q:\n%s", s, h.logs.String())
				}
			}
		})
	}
}

func TestMCPNestedSecretKeysAreNotRecorded(t *testing.T) {
	t.Parallel()
	h := startMCP(t)
	mcpPost(t, h, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"configure","arguments":{"settings":{"password":"nestedpw1","inner":{"api_key":"nestedkey2"}},"list":[{"token":"nestedtok3"}],"blob":"{\"password\":\"stringpw4\"}"}}}`, nil)
	ev := waitAttack(t, h.sink)
	for _, s := range []string{"nestedpw1", "nestedkey2", "nestedtok3", "stringpw4"} {
		if strings.Contains(ev.Meta["command"], s) || strings.Contains(h.logs.String(), s) {
			t.Errorf("nested secret %q recorded: %q", s, ev.Meta["command"])
		}
	}
	if !strings.Contains(ev.Meta["command"], "settings=<object>") || !strings.Contains(ev.Meta["command"], "list=<array>") {
		t.Errorf("command = %q", ev.Meta["command"])
	}
}

func TestMCPInvalidUTF8Arguments(t *testing.T) {
	t.Parallel()
	h := startMCP(t)
	// Raw invalid UTF-8 bytes inside JSON strings (encoding/json replaces them).
	body := "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"run\xff\xfe\",\"arguments\":{\"k\xc3\":\"v\xff\xfe\x80end\",\"q\":\"\xed\xa0\x80\"}}}"
	res := mcpPost(t, h, body, nil)
	if res.status != 200 {
		t.Fatalf("status = %d", res.status)
	}
	ev := waitAttack(t, h.sink)
	for k, v := range ev.Meta {
		if !utf8.ValidString(v) {
			t.Errorf("meta %s is not valid UTF-8: %q", k, v)
		}
	}
	if !utf8.ValidString(h.logs.String()) {
		t.Error("log holds invalid UTF-8")
	}
	if !strings.Contains(ev.Meta["command"], "end") {
		t.Errorf("command = %q", ev.Meta["command"])
	}
}

// proxyHTTP sends one HTTP request behind a PROXY header, so the alert source is a
// public address, and waits for the response to finish.
func proxyHTTP(t *testing.T, addr, srcIP, method, target, body string, headers map[string]string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var b strings.Builder
	fmt.Fprintf(&b, "PROXY TCP4 %s 1.1.1.1 40000 80\r\n%s %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: %d\r\n", srcIP, method, target, len(body))
	for k, v := range headers {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("\r\n" + body)
	if _, err := io.WriteString(conn, b.String()); err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, conn)
}

// TestStubTrapsNoSecretReachesCrowdSec drives the mcp, docker and kubernetes traps
// with credentials inside command strings and argument values, through the real
// Sensor and CrowdSec sink, and checks that no secret value is in the pushed JSON.
// RAN_LOG_PASSWORDS=on must not change that.
func TestStubTrapsNoSecretReachesCrowdSec(t *testing.T) {
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

	cfg := &config.Config{
		Addrs:          map[string]string{"mcp": "127.0.0.1:0", "docker": "127.0.0.1:0", "kubernetes": "127.0.0.1:0"},
		PerProto:       make(map[string]config.ProtoConfig),
		ProxyProtocol:  true,
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}
	lim := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)
	mcpAddr := serveTrap(t, ctx, NewMCP(cfg, logger, m, lim, sensor))
	dockerAddr := serveTrap(t, ctx, NewDocker(cfg, logger, m, lim, sensor))
	kubeAddr := serveTrap(t, ctx, NewKubernetes(cfg, logger, m, lim, sensor))

	secrets := []string{
		"mcpbearer11", "mcpaws22", "mcpapikey33", "mcpnested44", "mcpjsonstr55", "mcpcookie66", "mcphdr77",
		"dockerbearer11", "dockerdbpw22", "dockerimgpw33", "dockercookie44", "dockerhdr55",
		"kubebearer11", "kubemysql22", "kubetoken33", "kubehdr44",
	}

	mcpBody, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "run_command", "arguments": map[string]any{
			"command":  "curl -H 'Authorization: Bearer mcpbearer11' http://x; AWS_SECRET=mcpaws22 run.sh; curl -H 'Cookie: sid=mcpcookie66'",
			"api_key":  "mcpapikey33",
			"settings": map[string]any{"password": "mcpnested44"},
			"blob":     `{"token":"mcpjsonstr55"}`,
		}},
	})
	proxyHTTP(t, mcpAddr, "8.8.8.1", "POST", "/mcp", string(mcpBody), map[string]string{"Authorization": "Bearer mcphdr77"})

	dockerBody, _ := json.Marshal(map[string]any{
		"Image": "https://u:dockerimgpw33@registry.example.org/app",
		"Cmd":   []string{"sh", "-c", "curl -H 'Authorization: Bearer dockerbearer11' x; DB_PASSWORD=dockerdbpw22 run; curl -H 'Cookie: s=dockercookie44'"},
	})
	proxyHTTP(t, dockerAddr, "8.8.8.2", "POST", "/containers/create", string(dockerBody), map[string]string{"Authorization": "Bearer dockerhdr55"})
	execBody, _ := json.Marshal(map[string]any{"Cmd": []string{"sh", "-c", "AWS_SECRET=dockerdbpw22 run"}})
	proxyHTTP(t, dockerAddr, "8.8.8.3", "POST", "/containers/abc/exec", string(execBody), nil)

	q := url.Values{}
	q.Add("command", "curl -H 'Authorization: Bearer kubebearer11' x")
	q.Add("command", "MYSQL_PWD=kubemysql22 mysql")
	q.Add("command", "--token kubetoken33")
	proxyHTTP(t, kubeAddr, "8.8.8.4", "POST", "/run/default/pod/ctr?"+q.Encode(), "", map[string]string{"Authorization": "Bearer kubehdr44"})

	waitFor(t, func() bool { return lapi.acceptedCount() >= 4 })
	time.Sleep(300 * time.Millisecond)

	lapi.mu.Lock()
	defer lapi.mu.Unlock()
	raw, err := json.Marshal(lapi.accepted)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range secrets {
		if strings.Contains(string(raw), s) {
			t.Errorf("secret %q reached CrowdSec:\n%s", s, raw)
		}
	}
	for _, want := range []string{"tools/call run_command", "docker create", "docker exec", "token_hash"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("pushed JSON lacks %q:\n%s", want, raw)
		}
	}
}
