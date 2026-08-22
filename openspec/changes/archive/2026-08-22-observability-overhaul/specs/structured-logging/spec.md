## ADDED Requirements

### Requirement: Consistent action field
Every session log event SHALL include an `action` field with one of these bounded values: `connect`, `disconnect`, `auth_attempt`, `command`, `payload`, `rejected`, `error`.

#### Scenario: Loki query by action
- **WHEN** a Loki query filters `{app="ran"} | json | action="auth_attempt"`
- **THEN** all credential capture events across all protocols are returned, including SIP

### Requirement: Normalized log messages
Log methods SHALL use static message strings that do not embed variable data. Variable data SHALL only appear in structured fields.

#### Scenario: Connect message
- **WHEN** `LogConnect()` is called
- **THEN** the `msg` field is `"session started"` (not `"ssh connect from 1.2.3.4:54321"`)

#### Scenario: Disconnect message
- **WHEN** `LogDisconnect()` is called
- **THEN** the `msg` field is `"session ended"`

#### Scenario: Auth attempt message
- **WHEN** `LogAuthAttempt()` is called
- **THEN** the `msg` field is `"credentials captured"`

#### Scenario: Command message
- **WHEN** `LogCommand()` is called
- **THEN** the `msg` field is `"command received"`

#### Scenario: Payload message
- **WHEN** `LogPayload()` is called
- **THEN** the `msg` field is `"payload received"`

### Requirement: Connect logged at Info level
`LogConnect()` SHALL log at `Info` level so connection events are visible at the default log level.

#### Scenario: Default log level
- **WHEN** `RAN_LOG_LEVEL` is unset (default `info`)
- **THEN** connect events appear in the log output

### Requirement: Transport field on session
Every session SHALL include a `transport` field in its base logger fields with value `"tcp"` or `"udp"`.

#### Scenario: TCP session
- **WHEN** an SSH session is created
- **THEN** all log events for that session include `"transport": "tcp"`

#### Scenario: UDP session
- **WHEN** a DNS packet creates a session
- **THEN** all log events for that session include `"transport": "udp"`

### Requirement: Consistent source_ip field
All log events referencing a source IP SHALL use the field name `source_ip`. No component SHALL use `ip` or other variants.

#### Scenario: CrowdSec logs
- **WHEN** the CrowdSec alerter logs a cache hit or alert push
- **THEN** the IP field is `"source_ip"`, not `"ip"`

#### Scenario: Loki cross-component query
- **WHEN** a Loki query filters `| json | source_ip="1.2.3.4"`
- **THEN** both session events and CrowdSec events for that IP are returned

### Requirement: Structured rejected events
Connection rejections SHALL be logged with `action="rejected"` at Warn level, including `protocol`, `transport`, `dest_port`, `source_ip`, and `reason` fields.

#### Scenario: TCP rate limit rejection
- **WHEN** an SSH connection is rejected by the rate limiter
- **THEN** a log event is emitted with `action="rejected"`, `protocol="ssh"`, `transport="tcp"`, `dest_port=2222`, `source_ip="1.2.3.4"`, `reason="rate_limit"`

#### Scenario: UDP rate limit rejection
- **WHEN** a DNS packet is rejected by the rate limiter
- **THEN** a log event is emitted with `action="rejected"`, `protocol="dns"`, `transport="udp"`, `dest_port=53`, `source_ip="1.2.3.4"`, `reason="rate_limit"`
