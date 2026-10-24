## ADDED Requirements

### Requirement: First byte capture
The `catchall` trap SHALL accept TCP connections on the configured ports, wait for the first bytes up to a short read window and log at most 256 bytes as hex and printable text.

#### Scenario: Client sends data
- **WHEN** a client sends 300 bytes
- **THEN** 256 bytes are logged, 300 payload bytes are not stored beyond the bound and the session is classified `attack`

#### Scenario: Silent connect
- **WHEN** a client connects and sends nothing until the read window ends
- **THEN** the session is a `probe`

### Requirement: Protocol sniffing
The trap SHALL label the first bytes as `tls`, `http`, `smb`, `ssh`, `rdp` or `unknown` and add the label to the log and alert meta. The label set SHALL be fixed.

#### Scenario: TLS ClientHello
- **WHEN** the first bytes start with a TLS handshake record
- **THEN** the label is `tls`

### Requirement: Bounded behavior
The trap SHALL not respond with protocol data, SHALL close after the first read window and SHALL use the shared limiter and session timeout.

#### Scenario: Flood
- **WHEN** a source opens more connections than `RAN_MAX_PER_IP`
- **THEN** the excess connections are rejected before a goroutine is spawned
