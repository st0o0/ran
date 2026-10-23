## Purpose

Shared UDP listener base providing packet reception, rate limiting, and session tracking for all UDP-based honeypot traps.
## Requirements
### Requirement: UDP listener setup
The `UDPTrap` SHALL accept multiple listen addresses. For each address, it SHALL open a `net.PacketConn` and run a read loop in its own goroutine. The destPort per packet SHALL be derived from the `PacketConn`'s local address, not stored at construction time.

#### Scenario: Single UDP address (backward compatible)
- **WHEN** a UDP trap is created with address `[":53"]`
- **THEN** one `PacketConn` is opened and packets are handled with destPort 53

#### Scenario: Multiple UDP addresses
- **WHEN** a UDP trap is created with addresses `[":53", ":5353"]`
- **THEN** two `PacketConn` instances are opened, each in its own read goroutine, and packets on port 5353 report destPort 5353

#### Scenario: Close stops all connections
- **WHEN** `Stop()` is called on a multi-port UDP trap
- **THEN** all `PacketConn` instances are closed and all read goroutines exit

### Requirement: Constructor accepts address list
`NewUDP` SHALL accept `addrs []string` instead of a single `addr string`. The `destPort` field SHALL be removed; destPort is derived per-packet from the conn's local address.

#### Scenario: Factory passes address list
- **WHEN** the DNS trap factory calls `NewUDP` with `cfg.TrapAddrs("dns")`
- **THEN** the UDP trap is created with the address list from config

### Requirement: UDP rate limiting
The system SHALL apply the shared Limiter to UDP source IPs, rejecting packets from IPs that exceed `MaxPerIP`.

#### Scenario: Rate-limited UDP source
- **WHEN** a UDP source IP exceeds the per-IP limit
- **THEN** the packet SHALL be silently dropped and a warning logged

### Requirement: UDP session tracking
The system SHALL create a Session for each received UDP packet, logging connect and disconnect and recording metrics. The `readLoop` SHALL call `LogDisconnect()` after the packet handler returns, ensuring every session has both a connect and disconnect event.

#### Scenario: First packet from a new source
- **WHEN** a packet arrives from a previously unseen source IP+port
- **THEN** a new Session SHALL be created with protocol set to the trap name and transport set to `"udp"`
- **AND** `LogConnect` SHALL be called

#### Scenario: Packet handling completes
- **WHEN** a UDP packet handler finishes processing
- **THEN** `LogDisconnect()` SHALL be called on the session
- **AND** `RecordEnd()` SHALL be called, decrementing `ran_active_sessions`

#### Scenario: active_sessions gauge lifecycle
- **WHEN** a UDP packet arrives and is processed
- **THEN** `ran_active_sessions{protocol}` increments on session start
- **AND** decrements after the handler returns
- **AND** the gauge never leaks (monotonically increasing without decrements)

### Requirement: PacketHandler receives Session
`PacketHandler.HandlePacket` SHALL accept a `*Session` parameter instead of separate `src net.Addr` and `destPort int` parameters. The handler SHALL use the session's logger for all logging and call session methods (`LogAuthAttempt`, `LogPayload`, etc.) directly.

#### Scenario: DNS handler uses session
- **WHEN** the DNS handler processes a query
- **THEN** it calls `sess.LogPayload("dns_query", ...)` using the provided session
- **AND** it does NOT create its own session

#### Scenario: SIP handler uses session for auth
- **WHEN** the SIP handler detects an Authorization header
- **THEN** it calls `sess.LogAuthAttempt(...)` (not `sess.LogPayload("auth_attempt", ...)`)
- **AND** the event has `action="auth_attempt"` in the log output

#### Scenario: Handler accesses source info
- **WHEN** a handler needs the source IP or destination port
- **THEN** it reads `sess.SourceIP` and `sess.DestPort` from the session

### Requirement: UDP parse errors logged
UDP protocol handlers SHALL log parse failures instead of returning silently. Parse errors SHALL be logged via the session's logger with `action="error"` and `error_type="parse_failed"`.

#### Scenario: DNS packet too short
- **WHEN** a DNS packet shorter than 12 bytes arrives
- **THEN** the handler logs an error with `action="error"`, `error_type="parse_failed"`, `protocol="dns"`
- **AND** the handler returns without further processing

#### Scenario: NTP invalid mode
- **WHEN** an NTP packet with an unrecognized mode arrives
- **THEN** the handler logs an error with `error_type="parse_failed"` and returns

### Requirement: UDP traps never alert
UDP traps (dns, ntp, snmp, sip) SHALL NOT raise CrowdSec alerts, because UDP source addresses are spoofable. UDP handlers SHALL have no alerter, and the UDP trap constructors SHALL NOT accept one, so a UDP handler cannot alert at all. Logging and metrics SHALL continue. This supersedes any "alert CrowdSec" wording in the `trap-dns`, `trap-ntp`, `trap-snmp` and `trap-sip` specs.

#### Scenario: DNS query
- **WHEN** a DNS query arrives over UDP
- **THEN** a payload event is logged and metrics are updated
- **AND** no alert is passed to the CrowdSec alerter

### Requirement: UDP packet rate limiting
The UDP read loop SHALL apply a per-source token bucket (default 20 pkt/s, burst 40; a configured burst below the per-source rate SHALL be rejected at startup) and a global bucket (default 2000 pkt/s) before creating a session or spawning a goroutine. Dropped packets SHALL be counted in `ran_udp_rate_limited_total{protocol}` and logged at debug only. Per-source state SHALL be size-capped at 100000 sources; once the cap is reached only the global bucket applies to untracked sources. The limiter is per UDP trap, so the global bucket is per protocol.

#### Scenario: Packet flood from one source
- **WHEN** a source sends 10000 packets in one second
- **THEN** at most the burst plus rate times elapsed seconds are handled and the rest are dropped without spawning goroutines

#### Scenario: Many spoofed sources
- **WHEN** packets arrive from more sources than the per-source map cap
- **THEN** the global bucket still bounds the handled rate and map size stays capped

#### Scenario: Dropped packets are counted
- **WHEN** the rate limiter drops packets from a flood
- **THEN** `ran_udp_rate_limited_total{protocol}` increases by the number of dropped packets

#### Scenario: Burst below per-source rate
- **WHEN** `RAN_UDP_RATE_BURST` is smaller than `RAN_UDP_RATE_PER_SOURCE`
- **THEN** configuration loading fails with an error naming `RAN_UDP_RATE_BURST`

### Requirement: UDP Stop honours its context
`Stop(ctx)` on a UDP trap SHALL close all sockets and wait for in-flight packet handlers, and SHALL return `ctx.Err()` when the context ends before they finish.

#### Scenario: Handler stuck at shutdown
- **WHEN** a packet handler does not return before the `Stop` context deadline
- **THEN** `Stop` returns the context error at the deadline

