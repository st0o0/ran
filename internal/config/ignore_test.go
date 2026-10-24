package config

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func pfx(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

func TestParseIgnoreList(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []netip.Prefix
	}{
		{"empty", "", nil},
		{"only separators and spaces", " , ,, ", nil},
		{"ipv4", "8.8.8.8", pfx("8.8.8.8/32")},
		{"ipv6", "2606:4700:4700::1111", pfx("2606:4700:4700::1111/128")},
		{"cidr v4", "1.1.1.0/24", pfx("1.1.1.0/24")},
		{"cidr v6", "2606:4700:4700::/48", pfx("2606:4700:4700::/48")},
		{"cidr is masked", "1.1.1.77/24", pfx("1.1.1.0/24")},
		{"mapped address", "::ffff:8.8.8.8", pfx("8.8.8.8/32")},
		{"mapped cidr", "::ffff:1.1.1.0/120", pfx("1.1.1.0/24")},
		{"duplicates", "8.8.8.8,8.8.8.8, ::ffff:8.8.8.8 ,8.8.8.8/32", pfx("8.8.8.8/32")},
		{"whitespace and empty entries", " 8.8.8.8 ,, 1.1.1.0/24 ,", pfx("8.8.8.8/32", "1.1.1.0/24")},
		{"spec example", "8.8.8.8,1.1.1.0/24,2606:4700:4700::1111", pfx("8.8.8.8/32", "1.1.1.0/24", "2606:4700:4700::1111/128")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseIgnoreList("RAN_IGNORE_IPS", tc.raw)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseIgnoreListInvalid(t *testing.T) {
	for _, bad := range []string{
		"not-an-ip", "8.8.8.256", "8.8.8.0/33", "8.8.8.8/", "/24", "fe80::1%eth0",
		"fe80::1%eth0/64", "::ffff:1.1.1.0/64", "example.com", "8.8.8.8;1.1.1.1", "1.1.1",
	} {
		_, err := ParseIgnoreList("RAN_IGNORE_IPS", "8.8.8.8, "+bad)
		if err == nil {
			t.Errorf("%q accepted, want error", bad)
			continue
		}
		if !strings.Contains(err.Error(), "RAN_IGNORE_IPS") || !strings.Contains(err.Error(), bad) {
			t.Errorf("error for %q must name the variable and the entry: %v", bad, err)
		}
	}
}

func TestLoadIgnoreIPs(t *testing.T) {
	c, err := Load(envFunc(map[string]string{"RAN_TRAPS": "ssh", "RAN_IGNORE_IPS": "8.8.8.8,1.1.1.0/24,2606:4700:4700::1111"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.IgnoreIPs) != 3 {
		t.Fatalf("IgnoreIPs = %v, want 3 ranges", c.IgnoreIPs)
	}

	c, err = Load(envFunc(map[string]string{"RAN_TRAPS": "ssh"}))
	if err != nil || len(c.IgnoreIPs) != 0 {
		t.Fatalf("default: IgnoreIPs = %v, err = %v, want none", c.IgnoreIPs, err)
	}

	_, err = Load(envFunc(map[string]string{"RAN_TRAPS": "ssh", "RAN_IGNORE_IPS": "8.8.8.8,not-an-ip"}))
	if err == nil || !strings.Contains(err.Error(), "not-an-ip") {
		t.Errorf("want an error naming not-an-ip, got %v", err)
	}
}

func TestIsIgnored(t *testing.T) {
	c, err := Load(envFunc(map[string]string{"RAN_TRAPS": "ssh", "RAN_IGNORE_IPS": "8.8.8.8,1.1.1.0/24,2606:4700:4700::/48"}))
	if err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]bool{
		"8.8.8.8":                true,
		"::ffff:8.8.8.8":         true,
		"8.8.4.4":                false,
		"1.1.1.200":              true,
		"1.1.2.1":                false,
		"2606:4700:4700::1111":   true,
		"2606:4700:4701::1":      false,
		"fe80::1%eth0":           false,
		"2606:4700:4700::1%eth0": true,
		"":                       false,
		"garbage":                false,
	} {
		if got := c.IsIgnored(ip); got != want {
			t.Errorf("IsIgnored(%q) = %v, want %v", ip, got, want)
		}
	}
	if (&Config{}).IsIgnored("8.8.8.8") {
		t.Error("empty list must ignore nothing")
	}
}

// FuzzParseIgnoreList: never panic, and every accepted prefix is valid,
// masked, unmapped and unique; the number of prefixes is bounded by the input.
func FuzzParseIgnoreList(f *testing.F) {
	f.Add("8.8.8.8,1.1.1.0/24,2606:4700:4700::1111")
	f.Add(" ,::ffff:8.8.8.8, fe80::1%eth0 ,1.1.1.1/")
	f.Add("::ffff:1.1.1.0/120")
	f.Fuzz(func(t *testing.T, raw string) {
		got, err := ParseIgnoreList("RAN_IGNORE_IPS", raw)
		if err != nil {
			return
		}
		if len(got) > len(raw)/2+1 {
			t.Fatalf("%d prefixes from %d input bytes", len(got), len(raw))
		}
		seen := map[netip.Prefix]bool{}
		for _, p := range got {
			if !p.IsValid() || p != p.Masked() || p.Addr().Is4In6() || p.Addr().Zone() != "" || seen[p] {
				t.Fatalf("bad prefix %v in %v", p, got)
			}
			seen[p] = true
			if !MatchesPrefixes(got, p.Addr().String()) {
				t.Fatalf("%v does not match its own address", p)
			}
		}
	})
}
