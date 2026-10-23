## MODIFIED Requirements

### Requirement: Self-contained decisions
Alerts SHALL NOT embed decisions. Each alert SHALL have an empty `decisions` list and `remediation` set to `true`, so CrowdSec profiles decide whether and how long to ban. Scope SHALL be `Ip` (capital I) and the scenario `custom/ran-<protocol>-trap`.

#### Scenario: SSH attack alert
- **WHEN** an SSH session from 192.0.2.10 attempts credentials and an alert is sent
- **THEN** the alert has scenario `custom/ran-ssh-trap`, `source.scope` `Ip`, `source.value` `192.0.2.10`, `remediation` true, and no decisions

### Requirement: Non-blocking alert delivery
Alerts SHALL be sent via a buffered channel (capacity 256) consumed by a single worker goroutine. If the channel is full the alert SHALL be dropped, a warning logged, and `ran_crowdsec_alerts_dropped_total{protocol}` incremented. `Alert()` SHALL increment `ran_crowdsec_pipeline_total{stage="received"}` on every call, then one of `filtered`, `cooldown`, `queued` or `dropped`.

#### Scenario: Normal alert flow
- **WHEN** an attack-class session qualifies and no cooldown is active
- **THEN** `received` and `queued` are incremented

#### Scenario: Channel full
- **WHEN** 256 alerts are queued and another arrives
- **THEN** `received` and `dropped` are incremented and `ran_crowdsec_alerts_dropped_total{protocol}` is incremented

#### Scenario: Class not enabled
- **WHEN** a probe-class session arrives and `RAN_BAN_ON=attack,scan`
- **THEN** `received` and `filtered` are incremented and no alert is queued

#### Scenario: Cooldown active
- **WHEN** an alert for the same IP and class was queued less than `RAN_ALERT_COOLDOWN` ago
- **THEN** `received` and `cooldown` are incremented and no alert is queued

#### Scenario: Class escalation bypasses cooldown
- **WHEN** an IP in cooldown for `probe` produces an `attack` session
- **THEN** the alert is queued

## ADDED Requirements

### Requirement: Alert event metadata
Each alert event SHALL include meta keys `class` (`probe`, `attack` or `scan`), `protocol`, `dest_port`, `auth_attempts`, `commands` and `payload_bytes`, in addition to trap-specific meta.

#### Scenario: Class available to profiles
- **WHEN** an attack alert is pushed
- **THEN** `Alert.Events[0].GetMeta("class")` evaluates to `attack` in a CrowdSec profile

## REMOVED Requirements

### Requirement: Configurable ban duration
**Reason**: ran no longer decides ban duration; CrowdSec profiles do.
**Migration**: Configure `duration` or `duration_expr` in CrowdSec `profiles.yaml`.
