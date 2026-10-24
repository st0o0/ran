package main

import (
	"bytes"
	"context"
	"net/netip"
	"strings"
	"testing"
)

func TestCheckConfigIgnoreIPs(t *testing.T) {
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}
	var out, errb bytes.Buffer
	valid := map[string]string{"RAN_TRAPS": "ssh", "RAN_IGNORE_IPS": "8.8.8.8,1.1.1.0/24,2606:4700:4700::1111"}
	if code := checkConfig(env(valid), &out, &errb); code != 0 || !strings.Contains(out.String(), "3 ignored ranges") {
		t.Fatalf("valid list: exit %d, stdout %q, stderr %q", code, out.String(), errb.String())
	}

	out.Reset()
	errb.Reset()
	bad := map[string]string{"RAN_TRAPS": "ssh", "RAN_IGNORE_IPS": "8.8.8.8,not-an-ip"}
	if code := checkConfig(env(bad), &out, &errb); code != 1 || !strings.Contains(errb.String(), "not-an-ip") {
		t.Fatalf("invalid entry: exit %d, stderr %q, want exit 1 naming not-an-ip", code, errb.String())
	}
}

func TestCheckConfigSuccessLineAndWarnings(t *testing.T) {
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}
	run := func(ignore string) (int, string, string) {
		var out, errb bytes.Buffer
		code := checkConfig(env(map[string]string{"RAN_TRAPS": "ssh", "RAN_IGNORE_IPS": ignore}), &out, &errb)
		return code, out.String(), errb.String()
	}

	// Same line shape with and without a list; no warning for ordinary ranges.
	for ignore, ranges := range map[string]string{"": "0 ignored ranges", "8.8.8.8,1.1.1.0/24": "2 ignored ranges"} {
		code, out, errb := run(ignore)
		if code != 0 || !strings.Contains(out, "configuration ok (1 traps: [ssh], "+ranges+")") || errb != "" {
			t.Errorf("ignore %q: exit %d, stdout %q, stderr %q", ignore, code, out, errb)
		}
	}

	// A non-global address is accepted: the CrowdSec denylist is a separate rule.
	if code, out, errb := run("127.0.0.1"); code != 0 || !strings.Contains(out, "1 ignored ranges") || errb != "" {
		t.Errorf("127.0.0.1: exit %d, stdout %q, stderr %q, want accepted", code, out, errb)
	}

	// Very wide ranges are accepted with one warning each.
	code, out, errb := run("8.8.8.8,0.0.0.0/0,::/0")
	if code != 0 || !strings.Contains(out, "3 ignored ranges") {
		t.Fatalf("wide ranges: exit %d, stdout %q, stderr %q", code, out, errb)
	}
	for _, r := range []string{"0.0.0.0/0", "::/0"} {
		if !strings.Contains(errb, "very wide range "+r) {
			t.Errorf("stderr lacks a warning for %s: %q", r, errb)
		}
	}
	if strings.Contains(errb, "8.8.8.8") {
		t.Errorf("stderr warns about a narrow range: %q", errb)
	}
}

func TestRunWarnsAboutWideIgnoredRanges(t *testing.T) {
	cfg, logger, m, buf := testSetup(t, []string{"test-wide"}, nil)
	cfg.IgnoreIPs = []netip.Prefix{netip.MustParsePrefix("8.8.8.8/32"), netip.MustParsePrefix("0.0.0.0/0")}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = run(ctx, cfg, logger, m, nil)
	out := buf.String()
	if !strings.Contains(out, `"level":"WARN"`) || !strings.Contains(out, `"range":"0.0.0.0/0"`) {
		t.Errorf("startup log lacks the wide range warning: %s", out)
	}
	if strings.Contains(out, `"range":"8.8.8.8/32"`) {
		t.Errorf("startup log warns about a narrow range: %s", out)
	}
}

func TestRunLogsIgnoredRangeCount(t *testing.T) {
	cfg, logger, m, buf := testSetup(t, []string{"test-ign"}, nil)
	cfg.IgnoreIPs = []netip.Prefix{netip.MustParsePrefix("8.8.8.8/32"), netip.MustParsePrefix("1.1.1.0/24")}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = run(ctx, cfg, logger, m, nil)
	if !strings.Contains(buf.String(), `"ignored_ranges":2`) {
		t.Errorf("startup log lacks the ignored range count: %s", buf.String())
	}
}
