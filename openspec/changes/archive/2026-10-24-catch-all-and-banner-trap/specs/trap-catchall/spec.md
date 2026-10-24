## ADDED Requirements

### Requirement: First byte capture
The `catchall` trap SHALL accept TCP connections on the ports configured in `RAN_CATCHALL_ADDR`, wait for the first bytes up to a read window of 3 seconds (never longer than the session timeout), read once and log at most 256 bytes as hex and sanitized printable text. Bytes beyond the 256th SHALL NOT be read or stored.

#### Scenario: Client sends data
- **WHEN** a client sends 300 bytes
- **THEN** 256 bytes are logged, the rest is never stored and the session is classified `attack`

#### Scenario: Silent connect
- **WHEN** a client connects and sends nothing until the read window ends, or closes without sending
- **THEN** the session is a `probe` with outcome `probe`

#### Scenario: Window versus session timeout
- **WHEN** the session timeout is shorter than the read window
- **THEN** the connection ends at the session timeout

### Requirement: Protocol sniffing
The trap SHALL label the first bytes as `tls`, `http`, `smb`, `ssh`, `rdp` or `unknown` and add the label to the log (`sniffed_protocol`) and to the alert meta. The label set SHALL be fixed and empty input SHALL be `unknown`.

#### Scenario: TLS ClientHello
- **WHEN** the first bytes start with a TLS handshake record
- **THEN** the label is `tls`

#### Scenario: Unrecognized bytes
- **WHEN** the first bytes match none of the known signatures
- **THEN** the label is `unknown`

### Requirement: Bounded behavior
The trap SHALL NOT respond with protocol data, SHALL close after the first read, SHALL use the shared limiter and session timeout, SHALL use the fixed metrics protocol label `catchall` (never the port or client data), and SHALL honor the ignore list and PROXY protocol like other TCP traps. Destination ports SHALL count towards scan detection and `catchall` SHALL count as one protocol.

#### Scenario: Flood
- **WHEN** a source opens more connections than `RAN_MAX_PER_IP`
- **THEN** the excess connections are rejected before a goroutine is spawned

#### Scenario: Port spray
- **WHEN** one source sends data to five distinct catch-all ports within the scan window
- **THEN** the session is classified `scan`
