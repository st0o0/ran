package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCheckConfigAddresslessTraps(t *testing.T) {
	t.Parallel()
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}
	cases := []struct {
		name    string
		env     map[string]string
		code    int
		errPart string
	}{
		{"catchall without address", map[string]string{"RAN_TRAPS": "catchall"}, 1, "RAN_CATCHALL_ADDR"},
		{"banner without services", map[string]string{"RAN_TRAPS": "banner"}, 1, "RAN_BANNER_SERVICES"},
		{"catchall ok", map[string]string{"RAN_TRAPS": "catchall", "RAN_CATCHALL_ADDR": ":4444,:6000"}, 0, ""},
		{"banner ok", map[string]string{"RAN_TRAPS": "ssh,banner", "RAN_BANNER_SERVICES": `9999=custom:hello\r\n`}, 0, ""},
		{"banner too many", map[string]string{"RAN_TRAPS": "banner", "RAN_BANNER_SERVICES": "1=a:x,2=a:x,3=a:x,4=a:x,5=a:x,6=a:x,7=a:x,8=a:x,9=a:x,10=a:x,11=a:x"}, 1, `"11=a:x"`},
		{"banner bad entry", map[string]string{"RAN_TRAPS": "banner", "RAN_BANNER_SERVICES": "9999=ok:x,hello"}, 1, `"hello"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var out, errb bytes.Buffer
			code := checkConfig(env(tc.env), &out, &errb)
			if code != tc.code || !strings.Contains(errb.String(), tc.errPart) {
				t.Errorf("exit %d, stderr %q, want exit %d naming %q", code, errb.String(), tc.code, tc.errPart)
			}
		})
	}
}
