package alert

import "context"

// Class is the severity class of a session. CrowdSec profiles select on it.
type Class string

const (
	ClassProbe  Class = "probe"
	ClassAttack Class = "attack"
	ClassScan   Class = "scan"
)

// rank orders classes: scan > attack > probe. The zero value ranks lowest.
func (c Class) rank() int {
	switch c {
	case ClassProbe:
		return 1
	case ClassAttack:
		return 2
	case ClassScan:
		return 3
	default:
		return 0
	}
}

// Classes lists every valid class.
var Classes = []Class{ClassProbe, ClassAttack, ClassScan}

// SessionInfo is a snapshot of one trap session as seen by the sensor. SourceIP
// must come from the socket peer, never from attacker-controlled data.
type SessionInfo struct {
	SourceIP     string
	Protocol     string
	Transport    Transport
	DestPort     int
	AuthAttempts int
	Commands     int
	PayloadBytes int
	// AlertedClass is the highest class already reported for this session
	// ("" if none), so the sensor can report an escalation at session end.
	AlertedClass Class
}

// Transport is the network transport of a session. Only TCP sessions can alert,
// because UDP source addresses are spoofable.
type Transport string

const (
	TransportTCP Transport = "tcp"
	TransportUDP Transport = "udp"
)

// Alerter receives session activity from the traps.
type Alerter interface {
	// Alert reports activity during a session and returns the class the
	// session was evaluated as (empty if the alerter does not classify).
	Alert(ctx context.Context, info SessionInfo, meta map[string]string) Class
	// SessionEnd reports the end of a TCP session. It returns true if the
	// alerter aggregated the session's log output (probe sessions), so the
	// caller must not log per-session lines.
	SessionEnd(info SessionInfo) bool
	Close()
}

type NoopAlerter struct{}

func (NoopAlerter) Alert(context.Context, SessionInfo, map[string]string) Class { return "" }
func (NoopAlerter) SessionEnd(SessionInfo) bool                                 { return false }
func (NoopAlerter) Close()                                                      {}

// Event is a classified session handed to a Sink.
type Event struct {
	Class Class
	Info  SessionInfo
	Meta  map[string]string
}

// Sink delivers classified events, for example to CrowdSec.
type Sink interface {
	Submit(ctx context.Context, ev Event)
	Close()
}

// Classify returns attack when the session recorded an auth attempt, command or
// payload byte, otherwise probe. Scan is decided by the Sensor.
func Classify(info SessionInfo) Class {
	if info.AuthAttempts > 0 || info.Commands > 0 || info.PayloadBytes > 0 {
		return ClassAttack
	}
	return ClassProbe
}

// MaxClass returns the higher ranking of a and b.
func MaxClass(a, b Class) Class {
	if b.rank() > a.rank() {
		return b
	}
	return a
}
