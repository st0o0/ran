## ADDED Requirements

### Requirement: Shun after alert
With `RAN_SHUN=on`, after an alert was sent for a source, ran SHALL close new TCP connections from that source at accept time for the shun window, without creating a session or per-connection log lines, and SHALL count them in `ran_connections_rejected_total{reason="shun"}`.

#### Scenario: Persistent brute force
- **WHEN** a source sends an alert-worthy login attempt and then reconnects within the window
- **THEN** the reconnect is closed immediately, no session is logged, and the counter increases

#### Scenario: Window ends
- **WHEN** the shun window has passed and the source attacks again
- **THEN** the connection is served and a new alert is sent

#### Scenario: Ignored source
- **WHEN** a source in `RAN_IGNORE_IPS` triggers behavior that would alert
- **THEN** it is never shunned

#### Scenario: Probe only
- **WHEN** a source only probes and no alert is sent
- **THEN** it is never shunned

### Requirement: Repeat cooldown
After `RAN_REPEAT_AFTER` alerts for a source and class, the alert cooldown (and the shun window) SHALL be `RAN_REPEAT_COOLDOWN`. When the variable is unset the behavior SHALL equal the current cooldown behavior.

#### Scenario: Default unchanged
- **WHEN** `RAN_REPEAT_COOLDOWN` is not set
- **THEN** alerts are paced by `RAN_ALERT_COOLDOWN` only

#### Scenario: Relaxed after the ladder
- **WHEN** `RAN_REPEAT_AFTER=5` and `RAN_REPEAT_COOLDOWN=12h` and a source has sent five alerts
- **THEN** the sixth alert is allowed only after 12 hours

### Requirement: Summary and bounds
Suppressed connections SHALL be reported as one `shun summary` log line per source and window with a bounded protocol list, metric labels SHALL come from a fixed set, and the offender table SHALL be bounded with FIFO eviction.

#### Scenario: Flood of unique sources
- **WHEN** more unique sources alert than the table holds
- **THEN** memory stays bounded, the oldest entries are evicted and no error occurs
