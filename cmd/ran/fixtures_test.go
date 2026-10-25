package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckConfigHTTPFixtures(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	run := func(traps, file string) (int, string, string) {
		env := map[string]string{"RAN_TRAPS": traps, "RAN_HTTP_FIXTURES": file}
		var out, errb bytes.Buffer
		code := checkConfig(func(k string) string { return env[k] }, &out, &errb)
		return code, out.String(), errb.String()
	}

	ok := write("ok.json", `{"fixtures":[{"path":"/status","body":"ok"},{"path":"/b"}]}`)
	if code, out, errb := run("http", ok); code != 0 || !strings.Contains(out, "RAN_HTTP_FIXTURES ok (2 operator fixtures)") || errb != "" {
		t.Errorf("valid: exit %d, stdout %q, stderr %q", code, out, errb)
	}

	big := write("big.json", `{"fixtures":[{"path":"/ok"},{"path":"/big","body":"`+strings.Repeat("a", 8193)+`"}]}`)
	if code, _, errb := run("https", big); code != 1 || !strings.Contains(errb, `entry 2 (path "/big")`) || !strings.Contains(errb, "RAN_HTTP_FIXTURES") {
		t.Errorf("oversized body: exit %d, stderr %q, want exit 1 naming the entry", code, errb)
	}

	dup := write("dup.json", `{"fixtures":[{"path":"/a"},{"path":"/a"}]}`)
	if code, _, errb := run("http", dup); code != 1 || !strings.Contains(errb, `entry 2 (path "/a")`) {
		t.Errorf("duplicate: exit %d, stderr %q", code, errb)
	}

	if code, _, errb := run("http", filepath.Join(dir, "missing.json")); code != 1 || !strings.Contains(errb, "RAN_HTTP_FIXTURES") {
		t.Errorf("missing file: exit %d, stderr %q", code, errb)
	}
}
