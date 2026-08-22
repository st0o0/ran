## MODIFIED Requirements

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
