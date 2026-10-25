package config

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
)

// ProxyTrustAnyValue is the explicit RAN_PROXY_TRUSTED value that trusts every
// peer. It keeps the pre-allowlist behavior and is meant as a migration aid.
const ProxyTrustAnyValue = "any"

// ProxyTrust decides which socket peers may send PROXY protocol headers.
//
// A nil *ProxyTrust has two meanings that depend on the caller. Its methods
// (Trusts, Any) treat nil as "trusts nobody", so code that wraps a listener
// with a nil value fails closed. At the listener level, trap.ListenMultiTCP
// treats nil as "PROXY protocol off" and does not wrap the listener at all,
// which is what Config.ProxyTrust returns when RAN_PROXY_PROTOCOL is off.
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
// RAN_PROXY_PROTOCOL is off. Callers must read nil as "protocol off, do not
// wrap the listener", not as an empty trust set; a non-nil result with an empty
// list trusts nobody.
func (c *Config) ProxyTrust() *ProxyTrust {
	if !c.ProxyAny() {
		return nil
	}
	return NewProxyTrust(c.ProxyTrusted, c.ProxyTrustAny)
}

// ProxyTrustedUnused reports a RAN_PROXY_TRUSTED setting that has no effect
// because RAN_PROXY_PROTOCOL is off.
func (c *Config) ProxyTrustedUnused() bool {
	return !c.ProxyAny() && (c.ProxyTrustAny || len(c.ProxyTrusted) > 0)
}

// ParseProxyProtocol parses RAN_PROXY_PROTOCOL: on/true/yes/1 (all TCP traps),
// off/false/no/0 or empty (none), or a comma-separated list of TCP trap names.
// It returns the sorted, de-duplicated list in traps. A name that is not a valid
// trap, or that names a UDP trap, is an error naming the entry.
func ParseProxyProtocol(raw string) (all bool, traps []string, err error) {
	v := strings.ToLower(strings.TrimSpace(raw))
	switch v {
	case "", "off", "false", "no", "0":
		return false, nil, nil
	case "on", "true", "yes", "1":
		return true, nil, nil
	}
	seen := make(map[string]bool)
	for _, name := range strings.Split(v, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if UDPTraps[name] {
			return false, nil, fmt.Errorf("RAN_PROXY_PROTOCOL: %q is a UDP trap; UDP traps cannot use PROXY protocol, remove it from the list", name)
		}
		if !ValidTraps[name] {
			return false, nil, fmt.Errorf("RAN_PROXY_PROTOCOL: unknown trap %q; use on, off or a comma-separated list of TCP traps (valid: %s)", name, strings.Join(ValidTrapNames(), ", "))
		}
		if !seen[name] {
			seen[name] = true
			traps = append(traps, name)
		}
	}
	if len(traps) == 0 {
		return false, nil, nil
	}
	sort.Strings(traps)
	return false, traps, nil
}

// ProxyProtocolFor reports whether the named trap requires a PROXY header from a
// trusted peer. UDP traps never do.
func (c *Config) ProxyProtocolFor(name string) bool {
	if UDPTraps[name] {
		return false
	}
	return c.ProxyProtocol || c.ProxyTraps[name]
}

// ProxyAny reports whether at least one trap uses PROXY protocol.
func (c *Config) ProxyAny() bool {
	return c.ProxyProtocol || len(c.ProxyTraps) > 0
}

// ProxyTrapNames returns the enabled traps that expect a PROXY header, in
// RAN_TRAPS order.
func (c *Config) ProxyTrapNames() []string {
	var out []string
	for _, name := range c.Traps {
		if c.ProxyProtocolFor(name) {
			out = append(out, name)
		}
	}
	return out
}

// ProxyTrustFor returns the trust set for the named trap's listener, or nil when
// that trap does not use PROXY protocol (do not wrap the listener).
func (c *Config) ProxyTrustFor(name string) *ProxyTrust {
	if !c.ProxyProtocolFor(name) {
		return nil
	}
	return NewProxyTrust(c.ProxyTrusted, c.ProxyTrustAny)
}

// FormatPrefixes renders prefixes as a comma-separated string for logs.
func FormatPrefixes(prefixes []netip.Prefix) string {
	parts := make([]string, len(prefixes))
	for i, p := range prefixes {
		parts[i] = p.String()
	}
	return strings.Join(parts, ",")
}
