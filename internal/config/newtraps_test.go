package config

import (
	"reflect"
	"testing"
)

func TestNewScanTargetDefaults(t *testing.T) {
	t.Parallel()
	c, err := Load(envFunc(map[string]string{"RAN_TRAPS": "docker,kubernetes,mongodb,telnet"}))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"docker": ":2375", "kubernetes": ":6443", "mongodb": ":27017", "telnet": ":23,:2323"}
	for name, addr := range want {
		if got := c.TrapAddr(name); got != addr {
			t.Errorf("TrapAddr(%s) = %q, want %q", name, got, addr)
		}
		if !ValidTraps[name] {
			t.Errorf("%s is not a valid trap", name)
		}
	}
	if got := c.TrapAddrs("telnet"); !reflect.DeepEqual(got, []string{":23", ":2323"}) {
		t.Errorf("TrapAddrs(telnet) = %v", got)
	}
}

func TestTelnetAddrOverrideReplacesBothDefaults(t *testing.T) {
	t.Parallel()
	c, err := Load(envFunc(map[string]string{"RAN_TRAPS": "telnet", "RAN_TELNET_ADDR": ":2323"}))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.TrapAddrs("telnet"); !reflect.DeepEqual(got, []string{":2323"}) {
		t.Errorf("TrapAddrs(telnet) = %v, want only :2323", got)
	}
}
