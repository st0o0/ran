## MODIFIED Requirements

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
