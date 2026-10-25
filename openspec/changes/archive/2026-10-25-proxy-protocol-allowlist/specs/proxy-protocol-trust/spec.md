## ADDED Requirements

### Requirement: Trusted proxy list
With `RAN_PROXY_PROTOCOL=on`, `RAN_PROXY_TRUSTED` SHALL list the IPs and CIDRs of peers allowed to send PROXY headers. The configuration SHALL be invalid when it is empty, unless it is exactly `any`.

#### Scenario: Missing list
- **WHEN** `RAN_PROXY_PROTOCOL=on` and `RAN_PROXY_TRUSTED` is empty
- **THEN** `ran check-config` exits 1 and explains the variable

#### Scenario: Explicit any
- **WHEN** `RAN_PROXY_TRUSTED=any`
- **THEN** the configuration loads and a warning is logged at startup

### Requirement: Untrusted peers
A connection whose socket peer is not in the trusted list SHALL be closed without reading a header and counted in `ran_proxy_protocol_dropped_total`.

#### Scenario: Forged header
- **WHEN** an untrusted peer sends a valid PROXY v2 header with a public source address
- **THEN** the connection is closed and no session, log of the claimed address or alert is created

#### Scenario: Trusted proxy
- **WHEN** a peer in the list sends a valid header
- **THEN** the header address is used as before

### Requirement: List format
`RAN_PROXY_TRUSTED` SHALL use the format of `RAN_IGNORE_IPS` (IPv4 and IPv6 addresses and CIDRs, whitespace, empty entries and duplicates tolerated, IPv4-mapped forms unmapped, zones rejected, at most 1024 distinct entries) or be exactly `any`. Ranges with fewer than 8 bits SHALL log a warning at startup and in `ran check-config`.

#### Scenario: Invalid entry
- **WHEN** `RAN_PROXY_TRUSTED` contains an entry that is not an IP, a CIDR or `any` on its own
- **THEN** the configuration is invalid and the error names the variable

### Requirement: Variable set while the protocol is off
With `RAN_PROXY_PROTOCOL` off, a set `RAN_PROXY_TRUSTED` SHALL be validated but have no effect and SHALL log a warning at startup and in `ran check-config`.

#### Scenario: Protocol off
- **WHEN** `RAN_PROXY_PROTOCOL` is off and `RAN_PROXY_TRUSTED=10.0.0.0/8`
- **THEN** the configuration loads, the list is ignored and a warning is logged

### Requirement: Peer check scope
The check SHALL use the socket peer address of the accepted connection (IPv4-mapped addresses unmapped), once per connection and before any state is created for it, never header content. It SHALL apply to every TCP trap, including HTTP based ones, and never to UDP. Dropping an untrusted peer SHALL be logged at debug level only, without any address, and SHALL not use a handshake slot. Trusted peers SHALL behave as before, including `LOCAL` and `UNKNOWN` headers keeping the proxy address.

#### Scenario: Untrusted peer without a header
- **WHEN** an untrusted peer sends plain bytes
- **THEN** the connection is closed and counted without being read
