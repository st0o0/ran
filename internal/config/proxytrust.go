package config

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// ProxyTrustAnyValue is the explicit RAN_PROXY_TRUSTED value that trusts every
// peer. It keeps the pre-allowlist behavior and is meant as a migration aid.
const ProxyTrustAnyValue = "any"

// ProxyTrust decides which socket peers may send PROXY protocol headers. A nil
// *ProxyTrust trusts nobody, so a listener that is built without a list fails
// closed.
type ProxyTrust struct {
	any      bool
	prefixes []netip.Prefix
}

// NewProxyTrust builds a trust set from parsed prefixes. any trusts every peer.
func NewProxyTrust(prefixes []netip.Prefix, any bool) *ProxyTrust {
	return &ProxyTrust{any: any, prefixes: prefixes}
}

// Any reports whether every peer is trusted.
func (t *ProxyTrust) Any() bool { return t != nil && t.any }

// Trusts reports whether the socket peer addr may send a PROXY header. Only the
// address of the accepted connection is looked at, never header content. An
// address that cannot be parsed is not trusted (unless the list is "any").
func (t *ProxyTrust) Trusts(addr net.Addr) bool {
	if t == nil {
		return false
	}
	if t.any {
		return true
	}
	if len(t.prefixes) == 0 || addr == nil {
		return false
	}
	var ip netip.Addr
	if ta, ok := addr.(*net.TCPAddr); ok {
		ip = ta.AddrPort().Addr()
	} else {
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return false
		}
		if ip, err = netip.ParseAddr(host); err != nil {
			return false
		}
	}
	return matchAddr(t.prefixes, ip)
}

func matchAddr(prefixes []netip.Prefix, ip netip.Addr) bool {
	ip = ip.WithZone("").Unmap()
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// ParseProxyTrusted parses RAN_PROXY_TRUSTED: a list in the format of
// RAN_IGNORE_IPS, or exactly "any". An empty value yields an empty list.
func ParseProxyTrusted(raw string) (prefixes []netip.Prefix, any bool, err error) {
	if strings.TrimSpace(raw) == ProxyTrustAnyValue {
		return nil, true, nil
	}
	prefixes, err = ParseIgnoreList("RAN_PROXY_TRUSTED", raw)
	if err != nil {
		return nil, false, fmt.Errorf("%w (or the single value %q to trust every peer)", err, ProxyTrustAnyValue)
	}
	return prefixes, false, nil
}

// ProxyTrust returns the trust set for PROXY protocol listeners, or nil when
// RAN_PROXY_PROTOCOL is off.
func (c *Config) ProxyTrust() *ProxyTrust {
	if !c.ProxyProtocol {
		return nil
	}
	return NewProxyTrust(c.ProxyTrusted, c.ProxyTrustAny)
}

// ProxyTrustedUnused reports a RAN_PROXY_TRUSTED setting that has no effect
// because RAN_PROXY_PROTOCOL is off.
func (c *Config) ProxyTrustedUnused() bool {
	return !c.ProxyProtocol && (c.ProxyTrustAny || len(c.ProxyTrusted) > 0)
}
