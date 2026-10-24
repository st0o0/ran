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
