## MODIFIED Requirements

### Requirement: Self-contained decisions
Alerts SHALL NOT embed decisions. Each alert SHALL have an empty `decisions` list and `remediation` set to `true`, so CrowdSec profiles decide whether and how long to ban. Scope SHALL be `Ip` (capital I), `source.value` SHALL be set (an empty value creates no decision even if `source.ip` is set; `source.ip` SHALL also be set for geo enrichment), `simulated` SHALL be false, and the scenario SHALL be `custom/ran-<protocol>-trap`.

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

### Requirement: Graceful shutdown
On shutdown, the alerter SHALL stop the refresh goroutine and drain remaining alerts from the channel, bounded by the flush timeout (5 seconds, covering both posts and a re-login of one flush) and by the shared shutdown deadline of the process (9 seconds in total, of which traps and the metrics server use 4 seconds). If `Close` interrupts a failure hold, the first pending batch SHALL get one final attempt of at most 2 seconds.

#### Scenario: Shutdown stops refresh and drains alerts
- **WHEN** `Close()` is called with 3 alerts in the channel
- **THEN** the refresh goroutine stops and the worker attempts to push all 3 alerts before exiting

#### Scenario: Close during a failure hold
- **WHEN** `Close()` interrupts the hold after a failed push and alerts are pending
- **THEN** one final push of the first pending batch is attempted, and the rest is failed without posting if it fails

## ADDED Requirements

### Requirement: Alert event metadata
Class meta SHALL be set on the event so profiles use `Alert.Events[0].GetMeta("class")` (`Alert.GetMeta` reads only alert-level meta). Each alert event SHALL include meta keys `class` (`probe`, `attack` or `scan`), `protocol`, `dest_port`, `auth_attempts`, `commands` and `payload_bytes`, in addition to trap-specific meta.

#### Scenario: Class available to profiles
- **WHEN** an attack alert is pushed
- **THEN** `Alert.Events[0].GetMeta("class")` evaluates to `attack` in a CrowdSec profile

## REMOVED Requirements

### Requirement: Configurable ban duration
**Reason**: ran no longer decides ban duration; CrowdSec profiles do.
**Migration**: Configure `duration` or `duration_expr` in CrowdSec `profiles.yaml`.
