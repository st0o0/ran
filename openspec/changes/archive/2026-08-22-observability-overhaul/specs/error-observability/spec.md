## ADDED Requirements

### Requirement: Structured error events
Internal errors SHALL be logged with `action="error"` at Error level, including an `error_type` field and the `error` message.

#### Scenario: TCP accept error
- **WHEN** a TCP listener's `Accept()` returns an error (and context is not cancelled)
- **THEN** a log event is emitted with `action="error"`, `error_type="accept_failed"`, `protocol`, and the error message

#### Scenario: UDP parse error
- **WHEN** a UDP packet cannot be parsed by the protocol handler (e.g., DNS packet too short)
- **THEN** a log event is emitted with `action="error"`, `error_type="parse_failed"`, `protocol`, `source_ip`, and a description of the parse failure

#### Scenario: SSH handshake error
- **WHEN** an SSH handshake fails (e.g., `NewServerConn` returns an error)
- **THEN** a log event is emitted with `action="error"`, `error_type="handshake_failed"`, `protocol="ssh"`, `session_id`, and the error message

### Requirement: UDP parse failures are logged
UDP protocol handlers SHALL NOT silently return on parse failures. Every early return due to invalid data SHALL produce an error log event.

#### Scenario: DNS packet too short
- **WHEN** a DNS packet shorter than 12 bytes arrives
- **THEN** an error event is logged with `error_type="parse_failed"` and a description
- **AND** the handler returns without further processing

#### Scenario: SIP request with no lines
- **WHEN** a SIP packet with no parseable request line arrives
- **THEN** an error event is logged with `error_type="parse_failed"`
