package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseProxyProtocol(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		wantAll  bool
		wantList []string
	}{
		{"empty", "", false, nil},
		{"blank", "  ", false, nil},
		{"off", "off", false, nil},
		{"false", "FALSE", false, nil},
		{"zero", "0", false, nil},
		{"on", "on", true, nil},
		{"true", "True", true, nil},
		{"one", "1", true, nil},
		{"single", "http", false, []string{"http"}},
		{"list", "https,http", false, []string{"http", "https"}},
		{"whitespace and case", " HTTP , Https ,, ", false, []string{"http", "https"}},
		{"duplicates", "http,http", false, []string{"http"}},
		{"separators only", " , ", false, nil},
		{"addressless trap", "banner", false, []string{"banner"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			all, list, err := ParseProxyProtocol(tc.raw)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if all != tc.wantAll || !reflect.DeepEqual(list, tc.wantList) {
				t.Errorf("got all=%v list=%v, want all=%v list=%v", all, list, tc.wantAll, tc.wantList)
			}
		})
	}
}

func TestParseProxyProtocolInvalid(t *testing.T) {
	cases := []struct {
		raw      string
		contains string
	}{
		{"nosuchtrap", `"nosuchtrap"`},
		{"http,nosuchtrap", `"nosuchtrap"`},
		{"on,http", `"on"`},
		{"dns", "UDP traps cannot use PROXY protocol"},
		{"http, SNMP", "UDP traps cannot use PROXY protocol"},
		{"ntp", `"ntp"`},
	}
	for _, tc := range cases {
		_, _, err := ParseProxyProtocol(tc.raw)
		if err == nil {
			t.Errorf("%q accepted, want error", tc.raw)
			continue
		}
		if !strings.Contains(err.Error(), tc.contains) || !strings.Contains(err.Error(), "RAN_PROXY_PROTOCOL") {
			t.Errorf("error for %q = %v, want it to name the variable and contain %q", tc.raw, err, tc.contains)
		}
	}
}

func TestLoadProxyProtocolPerTrap(t *testing.T) {
	cases := []struct {
		name        string
		traps       string
		proxy       string
		trusted     string
		wantErr     string
		wantProxied []string
		wantUnused  bool
		wantMissing []string
	}{
		{"off", "ssh,http", "off", "", "", nil, false, nil},
		{"on", "ssh,http", "on", "10.0.0.0/8", "", []string{"ssh", "http"}, false, nil},
		{"list", "ssh,http,https", "http,https", "10.0.0.0/8", "", []string{"http", "https"}, false, nil},
		{"list needs trusted", "ssh,http", "http", "", "RAN_PROXY_TRUSTED", nil, false, nil},
		{"list with any", "ssh,http", "http", "any", "", []string{"http"}, false, nil},
		{"trusted unused when off", "ssh,http", "off", "10.0.0.0/8", "", nil, true, nil},
		{"trusted used by list", "ssh,http", "http", "10.0.0.0/8", "", []string{"http"}, false, nil},
		{"not in RAN_TRAPS only warns", "ssh", "http", "10.0.0.0/8", "", nil, false, []string{"http"}},
		{"unknown trap", "ssh,http", "web", "10.0.0.0/8", `"web"`, nil, false, nil},
		{"udp trap", "ssh,dns", "dns", "10.0.0.0/8", "UDP traps cannot use PROXY protocol", nil, false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Load(envFunc(map[string]string{
				"RAN_TRAPS": tc.traps, "RAN_PROXY_PROTOCOL": tc.proxy, "RAN_PROXY_TRUSTED": tc.trusted,
			}))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := c.ProxyTrapNames(); !reflect.DeepEqual(got, tc.wantProxied) {
				t.Errorf("ProxyTrapNames() = %v, want %v", got, tc.wantProxied)
			}
			for _, name := range c.Traps {
				want := false
				for _, p := range tc.wantProxied {
					want = want || p == name
				}
				if c.ProxyProtocolFor(name) != want {
					t.Errorf("ProxyProtocolFor(%q) = %v, want %v", name, !want, want)
				}
				if (c.ProxyTrustFor(name) != nil) != want {
					t.Errorf("ProxyTrustFor(%q) nil-ness does not follow ProxyProtocolFor", name)
				}
			}
			if c.ProxyTrustedUnused() != tc.wantUnused {
				t.Errorf("ProxyTrustedUnused() = %v, want %v", c.ProxyTrustedUnused(), tc.wantUnused)
			}
			if !reflect.DeepEqual(c.ProxyNotEnabled, tc.wantMissing) {
				t.Errorf("ProxyNotEnabled = %v, want %v", c.ProxyNotEnabled, tc.wantMissing)
			}
		})
	}
}

// UDP traps never use PROXY protocol, even with the global switch on.
func TestProxyProtocolForUDP(t *testing.T) {
	c := &Config{ProxyProtocol: true}
	if c.ProxyProtocolFor("dns") {
		t.Error("ProxyProtocolFor(dns) = true with RAN_PROXY_PROTOCOL=on")
	}
	if !c.ProxyProtocolFor("ssh") {
		t.Error("ProxyProtocolFor(ssh) = false with RAN_PROXY_PROTOCOL=on")
	}
}
