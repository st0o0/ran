package config_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/st0o0/ran/internal/config"
)

func fixturesJSON(entries ...string) string {
	return `{"fixtures":[` + strings.Join(entries, ",") + `]}`
}

func TestParseHTTPFixtures(t *testing.T) {
	t.Parallel()
	many := make([]string, config.MaxHTTPFixtures+1)
	for i := range many {
		many[i] = fmt.Sprintf(`{"path":"/p%d"}`, i)
	}
	exact := strings.Repeat("a", config.MaxHTTPFixtureBody)
	cases := []struct {
		name    string
		raw     string
		errPart string // empty means valid
		count   int
	}{
		{name: "valid", raw: fixturesJSON(`{"path":"/status","status":200,"headers":{"content-type":"text/plain"},"body":"ok"}`), count: 1},
		{name: "defaults", raw: fixturesJSON(`{"path":"/x"}`), count: 1},
		{name: "exact limit entries", raw: fixturesJSON(many[:config.MaxHTTPFixtures]...), count: config.MaxHTTPFixtures},
		{name: "too many", raw: fixturesJSON(many...), errPart: "65 entries"},
		{name: "exact limit body", raw: fixturesJSON(`{"path":"/x","body":"` + exact + `"}`), count: 1},
		{name: "too large body", raw: fixturesJSON(`{"path":"/ok"}`, `{"path":"/big","body":"`+exact+`a"}`), errPart: `entry 2 (path "/big"): body is 8193 bytes`},
		{name: "bad header name", raw: fixturesJSON(`{"path":"/h","headers":{"Set-Cookie":"a=b"}}`), errPart: `entry 1 (path "/h"): header "Set-Cookie" is not allowed`},
		{name: "content-length header", raw: fixturesJSON(`{"path":"/h","headers":{"Content-Length":"3"}}`), errPart: "not allowed"},
		{name: "header value newline", raw: fixturesJSON(`{"path":"/h","headers":{"Server":"a\r\nX: b"}}`), errPart: "printable ASCII"},
		{name: "header value too long", raw: fixturesJSON(`{"path":"/h","headers":{"Server":"` + strings.Repeat("a", 257) + `"}}`), errPart: "limit is 256"},
		{name: "header twice", raw: fixturesJSON(`{"path":"/h","headers":{"server":"a","SERVER":"b"}}`), errPart: "set twice"},
		{name: "duplicate path", raw: fixturesJSON(`{"path":"/a"}`, `{"path":"/b"}`, `{"path":"/a"}`), errPart: `entry 3 (path "/a"): path is already defined by entry 1`},
		{name: "path without slash", raw: fixturesJSON(`{"path":"status"}`), errPart: "must start with /"},
		{name: "empty path", raw: fixturesJSON(`{"body":"x"}`), errPart: "must start with /"},
		{name: "path control char", raw: fixturesJSON(`{"path":"/a\u0000b"}`), errPart: "printable ASCII"},
		{name: "path space", raw: fixturesJSON(`{"path":"/a b"}`), errPart: "printable ASCII"},
		{name: "path non ascii", raw: fixturesJSON(`{"path":"/ä"}`), errPart: "printable ASCII"},
		{name: "path query", raw: fixturesJSON(`{"path":"/a?b=1"}`), errPart: "must not contain ?"},
		{name: "path too long", raw: fixturesJSON(`{"path":"/` + strings.Repeat("a", 256) + `"}`), errPart: "limit is 256"},
		{name: "bad status", raw: fixturesJSON(`{"path":"/s","status":302}`), errPart: "status 302 is not allowed"},
		{name: "zero status", raw: fixturesJSON(`{"path":"/s","status":0}`), errPart: "status 0 is not allowed"},
		{name: "204 with body", raw: fixturesJSON(`{"path":"/s","status":204,"body":"x"}`), errPart: "204 must have an empty body"},
		{name: "204 empty", raw: fixturesJSON(`{"path":"/s","status":204}`), count: 1},
		{name: "unknown field", raw: fixturesJSON(`{"path":"/s","bodyy":"x"}`), errPart: "invalid JSON"},
		{name: "unknown top-level field", raw: `{"fixtures":[{"path":"/s"}],"extra":1}`, errPart: "invalid JSON"},
		{name: "bad json", raw: `{"fixtures":[`, errPart: "invalid JSON"},
		{name: "not json", raw: `path: /x`, errPart: "invalid JSON"},
		{name: "trailing data", raw: fixturesJSON(`{"path":"/s"}`) + `{}`, errPart: "after the top-level object"},
		{name: "wrong type", raw: fixturesJSON(`{"path":1}`), errPart: "invalid JSON"},
		{name: "empty list", raw: `{"fixtures":[]}`, errPart: "at least one"},
		{name: "empty file", raw: ``, errPart: "invalid JSON"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := config.ParseHTTPFixtures("RAN_HTTP_FIXTURES", []byte(tc.raw))
			if tc.errPart != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errPart) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.errPart)
				}
				if !strings.HasPrefix(err.Error(), "RAN_HTTP_FIXTURES") {
					t.Errorf("error does not name the variable: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tc.count {
				t.Fatalf("got %d fixtures, want %d", len(got), tc.count)
			}
		})
	}
}

func TestParseHTTPFixturesValues(t *testing.T) {
	t.Parallel()
	got, err := config.ParseHTTPFixtures("X", []byte(fixturesJSON(`{"path":"/status","headers":{"content-type":"text/plain","x-powered-by":"Foo"},"body":"ok"}`)))
	if err != nil {
		t.Fatal(err)
	}
	fx := got[0]
	if fx.Path != "/status" || fx.Status != 200 || fx.Body != "ok" || fx.Headers["Content-Type"] != "text/plain" || fx.Headers["X-Powered-By"] != "Foo" {
		t.Errorf("fixture = %+v", fx)
	}
}

func TestLoadHTTPFixturesFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	if got, err := config.LoadHTTPFixtures("X", write("ok.json", fixturesJSON(`{"path":"/status","body":"ok"}`))); err != nil || len(got) != 1 {
		t.Fatalf("valid file: %v %v", got, err)
	}
	if _, err := config.LoadHTTPFixtures("X", filepath.Join(dir, "missing.json")); err == nil || !strings.Contains(err.Error(), "cannot read fixture file") {
		t.Errorf("missing file: %v", err)
	}
	if _, err := config.LoadHTTPFixtures("X", dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("directory: %v", err)
	}
	big := write("big.json", fixturesJSON(`{"path":"/a"}`)+strings.Repeat(" ", config.MaxHTTPFixtureFile))
	if _, err := config.LoadHTTPFixtures("X", big); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("large file: %v", err)
	}
	// A file of exactly the limit is read (and then rejected only by content rules).
	exact := write("exact.json", fixturesJSON(`{"path":"/a"}`)+strings.Repeat(" ", config.MaxHTTPFixtureFile-len(fixturesJSON(`{"path":"/a"}`))))
	if _, err := config.LoadHTTPFixtures("X", exact); err != nil {
		t.Errorf("file at the limit: %v", err)
	}
}

func TestLoadHTTPFixturesEnv(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "f.json")
	if err := os.WriteFile(path, []byte(fixturesJSON(`{"path":"/status","body":"ok"}`)), 0o600); err != nil {
		t.Fatal(err)
	}
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

	c, err := config.Load(env(map[string]string{"RAN_TRAPS": "https", "RAN_HTTP_FIXTURES": path}))
	if err != nil || len(c.HTTPFixtures) != 1 {
		t.Fatalf("https only: %v %+v", err, c)
	}
	c, err = config.Load(env(map[string]string{"RAN_TRAPS": "ssh,http"}))
	if err != nil || len(c.HTTPFixtures) != 0 {
		t.Fatalf("unset: %v %+v", err, c)
	}
	// Not read when neither http nor https is enabled.
	c, err = config.Load(env(map[string]string{"RAN_TRAPS": "ssh", "RAN_HTTP_FIXTURES": filepath.Join(dir, "missing.json")}))
	if err != nil || len(c.HTTPFixtures) != 0 {
		t.Fatalf("no http trap: %v %+v", err, c)
	}
	if _, err = config.Load(env(map[string]string{"RAN_TRAPS": "http", "RAN_HTTP_FIXTURES": filepath.Join(dir, "missing.json")})); err == nil || !strings.Contains(err.Error(), "RAN_HTTP_FIXTURES") {
		t.Errorf("missing file with http: %v", err)
	}
}

func FuzzParseHTTPFixtures(f *testing.F) {
	f.Add([]byte(`{"fixtures":[{"path":"/status","status":200,"headers":{"Content-Type":"text/plain"},"body":"ok"}]}`))
	f.Add([]byte(`{"fixtures":[{"path":"/a"},{"path":"/a"}]}`))
	f.Add([]byte(`{"fixtures":[{"path":"/s","status":204,"body":"x"}]}`))
	f.Add([]byte(`{"fixtures":[{"path":"/\u0000","headers":{"Server":"a\r\nb"}}]}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := config.ParseHTTPFixtures("RAN_HTTP_FIXTURES", data)
		if err != nil {
			if len(err.Error()) > 1500 {
				t.Fatalf("error of %d bytes", len(err.Error()))
			}
			return
		}
		if len(got) == 0 || len(got) > config.MaxHTTPFixtures {
			t.Fatalf("%d fixtures", len(got))
		}
		seen := map[string]bool{}
		for _, fx := range got {
			if seen[fx.Path] {
				t.Fatalf("duplicate path %q", fx.Path)
			}
			seen[fx.Path] = true
			if fx.Path == "" || fx.Path[0] != '/' || len(fx.Path) > config.MaxHTTPFixturePath {
				t.Fatalf("bad path %q", fx.Path)
			}
			for i := 0; i < len(fx.Path); i++ {
				if c := fx.Path[i]; c <= 0x20 || c >= 0x7f || c == '?' || c == '#' {
					t.Fatalf("path %q has byte %#x", fx.Path, c)
				}
			}
			if !config.HTTPFixtureStatuses[fx.Status] {
				t.Fatalf("status %d", fx.Status)
			}
			if len(fx.Body) > config.MaxHTTPFixtureBody {
				t.Fatalf("body of %d bytes", len(fx.Body))
			}
			if len(fx.Headers) > config.MaxHTTPFixtureHeaders {
				t.Fatalf("%d headers", len(fx.Headers))
			}
			for k, v := range fx.Headers {
				if !config.HTTPFixtureHeaders[k] || len(v) > config.MaxHTTPFixtureHeader || strings.ContainsAny(v, "\r\n") {
					t.Fatalf("header %q: %q", k, v)
				}
			}
		}
	})
}
