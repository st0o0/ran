package trap

import (
	"net"
)

// shunner is implemented by the Sensor. A trap whose Reporter does not
// implement it (tests, no CrowdSec) never shuns.
type shunner interface {
	Shunned(ip string) bool
	ShunRejected(ip, protocol string)
}

// CanShun reports whether r can shun sources (it implements Shunned and
// ShunRejected, as the Sensor does) and, if it reports it, whether shunning is
// actually active (the Sensor's sink supplied a shun table with RAN_SHUN on).
// Startup uses it to fail loudly when RAN_SHUN is on but the reporter handed to
// the traps would silently never shun.
func CanShun(r Reporter) bool {
	if _, ok := r.(shunner); !ok {
		return false
	}
	if a, ok := r.(interface{ ShunActive() bool }); ok {
		return a.ShunActive()
	}
	return true
}

// closeIfShunned closes conn and reports true when its peer is in a shun window
// (RAN_SHUN). It runs at accept time, after PROXY handling (the peer address is
// the resolved source) and before any session, limiter slot, goroutine or log
// line exists. The decision lives in the Sensor, so the ignore list applies.
func closeIfShunned(r Reporter, protocol string, conn net.Conn) bool {
	s, ok := r.(shunner)
	if !ok {
		return false
	}
	// With shun off (the default) skip address parsing on every accept.
	if a, ok := r.(interface{ ShunActive() bool }); ok && !a.ShunActive() {
		return false
	}
	host, _ := ParseAddr(conn.RemoteAddr().String())
	if !s.Shunned(host) {
		return false
	}
	s.ShunRejected(host, protocol)
	_ = conn.Close()
	return true
}

// shunListener drops shunned connections inside Accept, for the http.Server
// based traps. It wraps the inner listener before any TLS wrapper, so a shunned
// peer never reaches the handshake.
type shunListener struct {
	net.Listener
	reporter Reporter
	protocol string
}

// newShunListener returns ln unchanged when the reporter cannot shun.
func newShunListener(ln net.Listener, r Reporter, protocol string) net.Listener {
	if _, ok := r.(shunner); !ok {
		return ln
	}
	return &shunListener{Listener: ln, reporter: r, protocol: protocol}
}

func (l *shunListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if closeIfShunned(l.reporter, l.protocol, conn) {
			continue
		}
		return conn, nil
	}
}
