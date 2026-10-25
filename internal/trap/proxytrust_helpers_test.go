package trap

import (
	"net/netip"

	"github.com/st0o0/ran/internal/config"
)

// loopbackPrefixes is the RAN_PROXY_TRUSTED value used by tests whose clients
// connect from the loopback interface.
var loopbackPrefixes = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
}

func loopbackTrust() *config.ProxyTrust { return config.NewProxyTrust(loopbackPrefixes, false) }

// trustFor returns the loopback trust set when on, nil (protocol off) otherwise.
func trustFor(on bool) *config.ProxyTrust {
	if !on {
		return nil
	}
	return loopbackTrust()
}
