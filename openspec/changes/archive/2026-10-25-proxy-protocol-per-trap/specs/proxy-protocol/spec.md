## ADDED Requirements

### Requirement: Per-trap PROXY protocol
`RAN_PROXY_PROTOCOL` SHALL accept `on`, `off` or a list of TCP trap names. With a list, only the named traps SHALL require a PROXY header from a peer in `RAN_PROXY_TRUSTED`; all other traps SHALL accept direct connections unchanged.

#### Scenario: Mixed deployment
- **WHEN** `RAN_PROXY_PROTOCOL=http` and a client connects directly to the `vnc` trap
- **THEN** the connection is served and the session source is the socket peer

#### Scenario: Proxied trap
- **WHEN** a trusted peer sends a valid PROXY header to the `http` trap
- **THEN** the session source is the address from the header

#### Scenario: Untrusted peer on a proxied trap
- **WHEN** an untrusted peer connects to the `http` trap
- **THEN** the connection is dropped before the header is read, as before

### Requirement: Validation
A list that names an unknown trap or a UDP trap SHALL fail startup with a message naming the entry, and a PROXY setting that applies to at least one trap SHALL still require `RAN_PROXY_TRUSTED`.

#### Scenario: UDP trap in the list
- **WHEN** `RAN_PROXY_PROTOCOL=dns`
- **THEN** startup fails and the message says UDP traps cannot use PROXY protocol
