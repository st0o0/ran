## ADDED Requirements

### Requirement: UDP listener pattern
The system SHALL provide a UDP listener base that reads packets from a `net.PacketConn`, dispatches them to a trap-specific handler, and supports graceful shutdown via context cancellation.

#### Scenario: UDP trap starts and receives packets
- **WHEN** a UDP trap is started with a configured address
- **THEN** it SHALL bind to that address using `net.ListenPacket` and read incoming datagrams in a loop

#### Scenario: UDP trap shuts down gracefully
- **WHEN** the context is cancelled
- **THEN** the UDP listener SHALL close the connection and stop reading packets without losing in-flight handler goroutines

### Requirement: UDP rate limiting
The system SHALL apply the shared Limiter to UDP source IPs, rejecting packets from IPs that exceed `MaxPerIP`.

#### Scenario: Rate-limited UDP source
- **WHEN** a UDP source IP exceeds the per-IP limit
- **THEN** the packet SHALL be silently dropped and a warning logged

### Requirement: UDP session tracking
The system SHALL create a Session for each unique source IP+port seen within a UDP trap, logging connect/disconnect and recording metrics.

#### Scenario: First packet from a new source
- **WHEN** a packet arrives from a previously unseen source IP+port
- **THEN** a new Session SHALL be created with protocol set to the trap name, and `LogConnect` SHALL be called
