package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/st0o0/ran/internal/config"
)

func proxyEnv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func loadProxyConfig(t *testing.T, protocol, trusted string) *config.Config {
	t.Helper()
	cfg, err := config.Load(proxyEnv(map[string]string{
		"RAN_TRAPS":          "ssh",
		"RAN_PROXY_PROTOCOL": protocol,
		"RAN_PROXY_TRUSTED":  trusted,
	}))
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return cfg
}

func TestLogProxyTrust(t *testing.T) {
	cases := []struct {
		name      string
		protocol  string
		trusted   string
		wantWarn  []string
		wantInfo  bool
		wantEmpty bool
	}{
		{name: "any warns", protocol: "on", trusted: "any", wantWarn: []string{"RAN_PROXY_TRUSTED=any"}},
		{name: "wide range warns", protocol: "on", trusted: "10.0.0.0/8,0.0.0.0/0", wantWarn: []string{"very wide range", "0.0.0.0/0"}, wantInfo: true},
		{name: "wide ipv6 range warns", protocol: "on", trusted: "::/0", wantWarn: []string{"very wide range", "::/0"}, wantInfo: true},
		{name: "set but protocol off warns", protocol: "off", trusted: "10.0.0.0/8", wantWarn: []string{"is set but RAN_PROXY_PROTOCOL is off"}},
		{name: "ordinary list only informs", protocol: "on", trusted: "10.0.0.0/8,2606:4700:4700::/48", wantInfo: true},
		{name: "threshold is /8 for both families", protocol: "on", trusted: "2606::/16,8.0.0.0/9", wantInfo: true},
		{name: "protocol off and unset is silent", protocol: "off", trusted: "", wantEmpty: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			logProxyTrust(logger, loadProxyConfig(t, tc.protocol, tc.trusted))
			out := buf.String()
			if tc.wantEmpty && out != "" {
				t.Errorf("expected no output, got %q", out)
			}
			for _, w := range tc.wantWarn {
				if !strings.Contains(out, "level=WARN") || !strings.Contains(out, w) {
					t.Errorf("output lacks WARN containing %q: %q", w, out)
				}
			}
			if len(tc.wantWarn) == 0 && strings.Contains(out, "level=WARN") {
				t.Errorf("unexpected warning: %q", out)
			}
			if got := strings.Contains(out, "PROXY protocol active"); got != tc.wantInfo {
				t.Errorf("info line present = %v, want %v: %q", got, tc.wantInfo, out)
			}
		})
	}
}

func TestCheckConfigProxyTrust(t *testing.T) {
	cases := []struct {
		name       string
		env        map[string]string
		wantCode   int
		wantStderr []string
		noStderr   bool
	}{
		{
			name:       "missing list exits 1",
			env:        map[string]string{"RAN_PROXY_PROTOCOL": "on"},
			wantCode:   1,
			wantStderr: []string{"RAN_PROXY_TRUSTED"},
		},
		{
			name:       "any warns",
			env:        map[string]string{"RAN_PROXY_PROTOCOL": "on", "RAN_PROXY_TRUSTED": "any"},
			wantStderr: []string{"RAN_PROXY_TRUSTED=any", "forge"},
		},
		{
			name:       "wide range warns",
			env:        map[string]string{"RAN_PROXY_PROTOCOL": "on", "RAN_PROXY_TRUSTED": "10.0.0.0/8,::/0"},
			wantStderr: []string{"RAN_PROXY_TRUSTED contains a very wide range ::/0"},
		},
		{
			name:       "set but protocol off warns",
			env:        map[string]string{"RAN_PROXY_TRUSTED": "10.0.0.0/8"},
			wantStderr: []string{"RAN_PROXY_TRUSTED is set but RAN_PROXY_PROTOCOL is off"},
		},
		{
			name:     "ordinary list is silent",
			env:      map[string]string{"RAN_PROXY_PROTOCOL": "on", "RAN_PROXY_TRUSTED": "10.0.0.0/8,2606::/16,8.0.0.0/9"},
			noStderr: true,
		},
		{
			name:     "wide range with protocol off only gets the unused warning",
			env:      map[string]string{"RAN_PROXY_TRUSTED": "0.0.0.0/0"},
			wantCode: 0, wantStderr: []string{"is set but RAN_PROXY_PROTOCOL is off"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{"RAN_TRAPS": "ssh"}
			for k, v := range tc.env {
				env[k] = v
			}
			var out, errb bytes.Buffer
			code := checkConfig(proxyEnv(env), &out, &errb)
			if code != tc.wantCode {
				t.Fatalf("exit %d, want %d (stdout %q, stderr %q)", code, tc.wantCode, out.String(), errb.String())
			}
			for _, w := range tc.wantStderr {
				if !strings.Contains(errb.String(), w) {
					t.Errorf("stderr lacks %q: %q", w, errb.String())
				}
			}
			if tc.noStderr && errb.Len() != 0 {
				t.Errorf("unexpected stderr: %q", errb.String())
			}
			if tc.wantCode == 1 && out.Len() != 0 {
				t.Errorf("stdout must be empty on failure: %q", out.String())
			}
		})
	}
}
