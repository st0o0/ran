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
