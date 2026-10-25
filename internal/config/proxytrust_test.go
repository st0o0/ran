package config

import (
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestParseProxyTrusted(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    []netip.Prefix
		wantAny bool
	}{
		{"empty", "", nil, false},
		{"separators only", " , ,, ", nil, false},
		{"ipv4", "10.0.0.1", pfx("10.0.0.1/32"), false},
		{"ipv6", "2606:4700:4700::1111", pfx("2606:4700:4700::1111/128"), false},
		{"cidr v4", "10.0.0.0/8", pfx("10.0.0.0/8"), false},
		{"cidr v6", "2001:db8::/32", pfx("2001:db8::/32"), false},
		{"mapped", "::ffff:10.0.0.1", pfx("10.0.0.1/32"), false},
		{"mapped cidr", "::ffff:10.0.0.0/104", pfx("10.0.0.0/8"), false},
		{"duplicates", "10.0.0.1, 10.0.0.1,::ffff:10.0.0.1,10.0.0.1/32", pfx("10.0.0.1/32"), false},
		{"whitespace", " 10.0.0.1 ,, 192.168.0.0/16 ,", pfx("10.0.0.1/32", "192.168.0.0/16"), false},
		{"any", "any", nil, true},
		{"any with spaces", "  any  ", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, anyFlag, err := ParseProxyTrusted(tc.raw)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) || anyFlag != tc.wantAny {
				t.Errorf("got %v any=%v, want %v any=%v", got, anyFlag, tc.want, tc.wantAny)
			}
		})
	}
}

func TestParseProxyTrustedInvalid(t *testing.T) {
	for _, bad := range []string{
		"not-an-ip", "10.0.0.256", "10.0.0.0/33", "fe80::1%eth0", "fe80::1%eth0/64",
		"ANY", "any,10.0.0.1", "10.0.0.1,any", "*", "example.com", "::ffff:10.0.0.0/64",
	} {
		_, _, err := ParseProxyTrusted(bad)
		if err == nil {
			t.Errorf("%q accepted, want error", bad)
			continue
		}
		if !strings.Contains(err.Error(), "RAN_PROXY_TRUSTED") || !strings.Contains(err.Error(), "any") {
			t.Errorf("error for %q must name the variable and mention any: %v", bad, err)
		}
	}
}

func TestParseProxyTrustedLimit(t *testing.T) {
	if got, _, err := ParseProxyTrusted(distinctIPv4s(MaxIgnoreEntries)); err != nil || len(got) != MaxIgnoreEntries {
		t.Fatalf("%d entries: got %d, err %v, want accepted", MaxIgnoreEntries, len(got), err)
	}
	_, _, err := ParseProxyTrusted(distinctIPv4s(MaxIgnoreEntries + 1))
	if err == nil || !strings.Contains(err.Error(), "1024") {
		t.Errorf("1025 entries: want a limit error, got %v", err)
	}
}

func TestProxyTrustedWideRanges(t *testing.T) {
	got, _, err := ParseProxyTrusted("10.0.0.0/8,0.0.0.0/0,::/0,2000::/3")
	if err != nil {
		t.Fatal(err)
	}
	want := pfx("0.0.0.0/0", "::/0", "2000::/3")
	if w := WideIgnoreRanges(got); !reflect.DeepEqual(w, want) {
		t.Errorf("wide ranges = %v, want %v", w, want)
	}
}

func TestLoadProxyTrustedMatrix(t *testing.T) {
	cases := []struct {
		name       string
		proxy      string
		trusted    string
		wantErr    bool
		wantAny    bool
		wantRanges int
		wantUnused bool
	}{
		{"off, unset", "off", "", false, false, 0, false},
		{"off, unset default", "", "", false, false, 0, false},
		{"off, list ignored with warning", "off", "10.0.0.0/8", false, false, 1, true},
		{"off, any ignored with warning", "off", "any", false, true, 0, true},
		{"on, unset", "on", "", true, false, 0, false},
		{"on, blank", "on", " , ", true, false, 0, false},
		{"on, list", "on", "10.0.0.0/8,2001:db8::/32", false, false, 2, false},
		{"on, any", "on", "any", false, true, 0, false},
		{"on, invalid", "on", "bogus", true, false, 0, false},
		{"off, invalid still rejected", "off", "bogus", true, false, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Load(envFunc(map[string]string{
				"RAN_TRAPS": "ssh", "RAN_PROXY_PROTOCOL": tc.proxy, "RAN_PROXY_TRUSTED": tc.trusted,
			}))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil {
				if !strings.Contains(err.Error(), "RAN_PROXY_TRUSTED") {
					t.Errorf("error must name RAN_PROXY_TRUSTED: %v", err)
				}
				if tc.trusted == "" || strings.TrimSpace(strings.ReplaceAll(tc.trusted, ",", "")) == "" {
					if !strings.Contains(err.Error(), "any") {
						t.Errorf("missing-list error must mention any: %v", err)
					}
				}
				return
			}
			if c.ProxyTrustAny != tc.wantAny || len(c.ProxyTrusted) != tc.wantRanges || c.ProxyTrustedUnused() != tc.wantUnused {
				t.Errorf("any=%v ranges=%d unused=%v, want any=%v ranges=%d unused=%v",
					c.ProxyTrustAny, len(c.ProxyTrusted), c.ProxyTrustedUnused(), tc.wantAny, tc.wantRanges, tc.wantUnused)
			}
			if (c.ProxyTrust() != nil) != (tc.proxy == "on") {
				t.Errorf("ProxyTrust() nil-ness does not follow RAN_PROXY_PROTOCOL")
			}
		})
	}
}

func TestProxyTrustTrusts(t *testing.T) {
	list := NewProxyTrust(pfx("10.0.0.0/8", "2001:db8::/32", "8.8.8.8/32"), false)
	tcp := func(s string) net.Addr { return net.TCPAddrFromAddrPort(netip.MustParseAddrPort(s)) }
	cases := []struct {
		name string
		t    *ProxyTrust
		addr net.Addr
		want bool
	}{
		{"v4 in range", list, tcp("10.1.2.3:5"), true},
		{"v4 host", list, tcp("8.8.8.8:5"), true},
		{"v6 in range", list, tcp("[2001:db8::1]:5"), true},
		{"mapped peer", list, tcp("[::ffff:10.1.2.3]:5"), true},
		{"outside", list, tcp("1.1.1.1:5"), false},
		{"v6 outside", list, tcp("[2606:4700:4700::1111]:5"), false},
		{"string addr in range", list, &net.UnixAddr{Name: "10.0.0.1:99", Net: "tcp"}, true},
		{"unparsable addr", list, &net.UnixAddr{Name: "pipe", Net: "pipe"}, false},
		{"nil addr", list, nil, false},
		{"nil trust", nil, tcp("10.1.2.3:5"), false},
		{"empty trust", NewProxyTrust(nil, false), tcp("10.1.2.3:5"), false},
		{"any", NewProxyTrust(nil, true), tcp("1.1.1.1:5"), true},
		{"any unparsable", NewProxyTrust(nil, true), &net.UnixAddr{Name: "pipe", Net: "pipe"}, true},
	}
	for _, tc := range cases {
		if got := tc.t.Trusts(tc.addr); got != tc.want {
			t.Errorf("%s: Trusts = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// FuzzParseProxyTrusted: never panic; accepted lists hold valid, masked,
// unmapped, unique prefixes; "any" never carries prefixes.
func FuzzParseProxyTrusted(f *testing.F) {
	f.Add("10.0.0.0/8,2001:db8::/32")
	f.Add("any")
	f.Add(" ,::ffff:10.0.0.1, fe80::1%eth0 ,any")
	f.Fuzz(func(t *testing.T, raw string) {
		got, anyFlag, err := ParseProxyTrusted(raw)
		if err != nil {
			return
		}
		if anyFlag && len(got) != 0 {
			t.Fatalf("any with prefixes %v", got)
		}
		seen := map[netip.Prefix]bool{}
		for _, p := range got {
			if !p.IsValid() || p != p.Masked() || p.Addr().Is4In6() || p.Addr().Zone() != "" || seen[p] {
				t.Fatalf("bad prefix %v in %v", p, got)
			}
			seen[p] = true
			tr := NewProxyTrust(got, false)
			if !tr.Trusts(net.TCPAddrFromAddrPort(netip.AddrPortFrom(p.Addr(), 1))) {
				t.Fatalf("%v does not trust its own address", p)
			}
		}
	})
}
