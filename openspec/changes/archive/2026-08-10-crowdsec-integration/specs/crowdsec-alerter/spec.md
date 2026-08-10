## ADDED Requirements

### Requirement: Alerter interface
The system SHALL define an `Alerter` interface with an `Alert(ctx, ip, protocol)` method. A no-op implementation SHALL be used when CrowdSec is disabled.

#### Scenario: CrowdSec disabled
- **WHEN** `RAN_CROWDSEC=off`
- **THEN** the no-op alerter is used and no alerts are sent

#### Scenario: CrowdSec enabled
- **WHEN** `RAN_CROWDSEC=on`
- **THEN** the CrowdSec alerter is used and alerts are pushed to LAPI

### Requirement: Non-blocking alert delivery
Alerts SHALL be sent via a buffered channel (capacity 256) consumed by a single worker goroutine. If the channel is full, the alert SHALL be dropped and a warning logged.

#### Scenario: Normal alert flow
- **WHEN** a trap detects an auth_attempt
- **THEN** the alert is sent to the channel and the trap continues immediately

#### Scenario: Channel full
- **WHEN** 256 alerts are queued and another arrives
- **THEN** the new alert is dropped and a warning is logged

### Requirement: CrowdSec LAPI push
The worker SHALL POST alerts to `{RAN_CROWDSEC_URL}/v1/alerts` with the API key in the `X-Api-Key` header.

#### Scenario: Successful push
- **WHEN** the LAPI is reachable
- **THEN** the alert is accepted and `ran_crowdsec_alerts_total{protocol,status="success"}` is incremented

#### Scenario: LAPI unreachable
- **WHEN** the LAPI returns an error or is unreachable
- **THEN** a warning is logged, `ran_crowdsec_alerts_total{protocol,status="failure"}` is incremented, and the worker continues

### Requirement: Self-contained decisions
Each alert SHALL include an embedded ban decision with the configured duration, IP scope, and protocol-specific scenario name.

#### Scenario: SSH trap alert
- **WHEN** an SSH auth_attempt from 1.2.3.4 triggers an alert
- **THEN** the alert contains scenario `custom/ran-ssh-trap`, source IP `1.2.3.4`, and a ban decision with the configured duration

### Requirement: Per-protocol scenario names
Alerts SHALL use scenario names: `custom/ran-ssh-trap`, `custom/ran-http-trap`, `custom/ran-mysql-trap`.

#### Scenario: MySQL trap
- **WHEN** a MySQL auth_attempt triggers an alert
- **THEN** the scenario is `custom/ran-mysql-trap`

### Requirement: Configurable ban duration
The ban duration SHALL be set via `RAN_CROWDSEC_BAN_DURATION` (default `4h`). A value of `0` SHALL mean permanent ban.

#### Scenario: Default ban
- **WHEN** `RAN_CROWDSEC_BAN_DURATION` is not set
- **THEN** the decision duration is `4h`

#### Scenario: Permanent ban
- **WHEN** `RAN_CROWDSEC_BAN_DURATION=0`
- **THEN** the decision duration is `0` (permanent)

### Requirement: Graceful shutdown
On shutdown, the worker SHALL drain remaining alerts from the channel (up to 5 seconds) before exiting.

#### Scenario: Shutdown with pending alerts
- **WHEN** the process receives SIGTERM with 3 alerts in the channel
- **THEN** the worker attempts to push all 3 before exiting
