package config_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/st0o0/ran/internal/config"
)

func TestParseBannerServices(t *testing.T) {
	t.Parallel()
	ten := make([]string, 10)
	eleven := make([]string, 11)
	for i := range eleven {
		e := "90" + string(rune('0'+i/10)) + string(rune('0'+i%10)) + "=svc:hi"
		eleven[i] = e
		if i < 10 {
			ten[i] = e
		}
	}
	exact := strings.Repeat("a", config.MaxBannerBytes)

	cases := []struct {
		name    string
		raw     string
		want    []config.BannerService
		errPart string // empty means valid
	}{
		{name: "single with escapes", raw: `9999=custom:hello\r\n`,
			want: []config.BannerService{{Port: 9999, Name: "custom", Banner: []byte("hello\r\n")}}},
		{name: "two entries and whitespace", raw: ` 21=ftp-old:220 ready\r\n, 2000=svc_1:x\ty\\z `,
			want: []config.BannerService{
				{Port: 21, Name: "ftp-old", Banner: []byte("220 ready\r\n")},
				{Port: 2000, Name: "svc_1", Banner: []byte("x\ty\\z ")},
			}},
		{name: "colon in banner", raw: `7000=a:SSH-2.0-x:y`,
			want: []config.BannerService{{Port: 7000, Name: "a", Banner: []byte("SSH-2.0-x:y")}}},
		{name: "escaped comma", raw: `7000=a:one\,two,7001=b:x`,
			want: []config.BannerService{
				{Port: 7000, Name: "a", Banner: []byte("one,two")},
				{Port: 7001, Name: "b", Banner: []byte("x")},
			}},
		{name: "empty entries skipped", raw: `,7000=a:x,,`,
			want: []config.BannerService{{Port: 7000, Name: "a", Banner: []byte("x")}}},
		{name: "ten entries", raw: strings.Join(ten, ","), want: nil},
		{name: "banner at the limit", raw: "7000=a:" + exact,
			want: []config.BannerService{{Port: 7000, Name: "a", Banner: []byte(exact)}}},

		{name: "empty", raw: ``, errPart: "RAN_BANNER_SERVICES"},
		{name: "only commas", raw: ` , ,`, errPart: "RAN_BANNER_SERVICES"},
		{name: "eleven entries", raw: strings.Join(eleven, ","), errPart: "more than 10"},
		{name: "no port", raw: `custom:hello`, errPart: `"custom:hello"`},
		{name: "empty port", raw: `=custom:hello`, errPart: "missing port"},
		{name: "port not a number", raw: `abc=custom:hello`, errPart: `"abc=custom:hello"`},
		{name: "port zero", raw: `0=custom:hello`, errPart: "invalid port"},
		{name: "port too large", raw: `70000=custom:hello`, errPart: "invalid port"},
		{name: "port with sign", raw: `+80=custom:hello`, errPart: "invalid port"},
		{name: "no name separator", raw: `9999=hello`, errPart: "missing ':'"},
		{name: "empty name", raw: `9999=:hello`, errPart: "missing service name"},
		{name: "name with upper case", raw: `9999=Custom:hello`, errPart: "service name may only contain"},
		{name: "name with space", raw: `9999=my svc:hello`, errPart: "service name may only contain"},
		{name: "name too long", raw: `9999=` + strings.Repeat("a", config.MaxBannerNameLen+1) + `:x`, errPart: "service name is longer"},
		{name: "empty banner", raw: `9999=custom:`, errPart: "banner is empty"},
		{name: "bad escape", raw: `9999=custom:hi\x41`, errPart: "unknown escape"},
		{name: "lone backslash", raw: `9999=custom:hi\`, errPart: "lone backslash"},
		{name: "duplicate port", raw: `9999=a:x,9999=b:y`, errPart: "port 9999 is used twice"},
		{name: "banner too long", raw: "7000=a:" + exact + "b", errPart: "257 bytes"},
		{name: "escapes count after decoding", raw: "7000=a:" + strings.Repeat(`\r`, 257), errPart: "257 bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := config.ParseBannerServices("RAN_BANNER_SERVICES", tc.raw)
			if tc.errPart != "" {
				if err == nil {
					t.Fatalf("accepted %q: %+v", tc.raw, got)
				}
				if !strings.Contains(err.Error(), "RAN_BANNER_SERVICES") || !strings.Contains(err.Error(), tc.errPart) {
					t.Errorf("error %q lacks %q or the variable name", err, tc.errPart)
				}
				return
			}
			if err != nil {
				t.Fatalf("rejected %q: %v", tc.raw, err)
			}
			if tc.want == nil {
				if len(got) != 10 {
					t.Errorf("got %d services, want 10", len(got))
				}
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestParseBannerServicesErrorQuotesAndBoundsEntry(t *testing.T) {
	t.Parallel()
	_, err := config.ParseBannerServices("RAN_BANNER_SERVICES", "x\x00y="+strings.Repeat("z", 5000))
	if err == nil {
		t.Fatal("want error")
	}
	if len(err.Error()) > 600 || strings.ContainsAny(err.Error(), "\x00\r\n") {
		t.Errorf("error is not bounded and printable: %q", err)
	}
}

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// An addressless trap without its address variable makes the configuration
// invalid, and the message names the variable.
func TestAddresslessTrapsRequireTheirVariable(t *testing.T) {
	t.Parallel()
	for trapName, variable := range config.AddresslessTraps {
		if _, has := config.DefaultPorts[trapName]; has {
			t.Errorf("%s must not have a default port", trapName)
		}
		if !config.ValidTraps[trapName] {
			t.Errorf("%s is not a valid trap", trapName)
		}
		_, err := config.Load(envOf(map[string]string{"RAN_TRAPS": "ssh," + trapName}))
		if err == nil || !strings.Contains(err.Error(), variable) {
			t.Errorf("%s without %s: err = %v, want it to name the variable", trapName, variable, err)
		}
	}
	// Not enabling the trap does not require the variable.
	if _, err := config.Load(envOf(map[string]string{"RAN_TRAPS": "ssh"})); err != nil {
		t.Errorf("ssh only: %v", err)
	}
}

func TestCatchallAddressAndBannerServicesLoad(t *testing.T) {
	t.Parallel()
	c, err := config.Load(envOf(map[string]string{
		"RAN_TRAPS":           "catchall,banner",
		"RAN_CATCHALL_ADDR":   ":4444, :6000",
		"RAN_BANNER_SERVICES": `9999=custom:hello\r\n,9998=other:x`,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.TrapAddrs("catchall"); !reflect.DeepEqual(got, []string{":4444", ":6000"}) {
		t.Errorf("catchall addrs = %v", got)
	}
	if len(c.BannerServices) != 2 || c.BannerServices[0].Port != 9999 {
		t.Errorf("banner services = %+v", c.BannerServices)
	}

	for name, env := range map[string]map[string]string{
		"bad catchall port":  {"RAN_TRAPS": "catchall", "RAN_CATCHALL_ADDR": "nonsense"},
		"bad banner service": {"RAN_TRAPS": "banner", "RAN_BANNER_SERVICES": "9999"},
	} {
		if _, err := config.Load(envOf(env)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// RAN_BANNER_SERVICES is only read when banner is enabled.
	if _, err := config.Load(envOf(map[string]string{"RAN_TRAPS": "ssh", "RAN_BANNER_SERVICES": "garbage"})); err != nil {
		t.Errorf("unused invalid RAN_BANNER_SERVICES rejected: %v", err)
	}
}

func FuzzParseBannerServices(f *testing.F) {
	f.Add(`9999=custom:hello\r\n`)
	f.Add(`1=a:x,2=b:y\,z,3=c:\\`)
	f.Add(`=:`)
	f.Add(`7000=a:` + strings.Repeat(`\n`, 300))
	f.Fuzz(func(t *testing.T, raw string) {
		got, err := config.ParseBannerServices("RAN_BANNER_SERVICES", raw)
		if err != nil {
			if len(err.Error()) > 700 {
				t.Fatalf("error of %d bytes", len(err.Error()))
			}
			return
		}
		if len(got) == 0 || len(got) > config.MaxBannerServices {
			t.Fatalf("%d services", len(got))
		}
		seen := map[int]bool{}
		for _, s := range got {
			if s.Port < 1 || s.Port > 65535 || seen[s.Port] {
				t.Fatalf("bad or duplicate port %d", s.Port)
			}
			seen[s.Port] = true
			if len(s.Banner) == 0 || len(s.Banner) > config.MaxBannerBytes {
				t.Fatalf("banner of %d bytes", len(s.Banner))
			}
			if s.Name == "" || len(s.Name) > config.MaxBannerNameLen {
				t.Fatalf("name %q", s.Name)
			}
			for _, c := range []byte(s.Name) {
				if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' && c != '-' {
					t.Fatalf("name %q has byte %q", s.Name, c)
				}
			}
		}
	})
}
