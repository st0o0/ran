## ADDED Requirements

### Requirement: Ignore list configuration
`RAN_IGNORE_IPS` SHALL accept a comma-separated list of IP addresses and CIDR ranges. An invalid entry SHALL make the configuration invalid and the error SHALL name the entry.

#### Scenario: Valid list
- **WHEN** `RAN_IGNORE_IPS=8.8.8.8,1.1.1.0/24,2606:4700:4700::1111`
- **THEN** the configuration loads and the startup log reports 3 ignored ranges

#### Scenario: Invalid entry
- **WHEN** `RAN_IGNORE_IPS=8.8.8.8,not-an-ip`
- **THEN** `ran check-config` exits 1 and names `not-an-ip`

### Requirement: Suppressed alerting
Sessions whose source is in the ignore list SHALL NOT raise alerts, SHALL NOT be recorded by the scan tracker and SHALL NOT be recorded in the probe summary. They SHALL still be served and logged with an `ignored` marker.

#### Scenario: Ignored attacker
- **WHEN** an ignored IP makes an SSH password attempt
- **THEN** the attempt is logged with `ignored=true`, no alert is queued and `ran_ignored_sessions_total{protocol="ssh"}` increases

#### Scenario: Scan state
- **WHEN** an ignored IP touches ssh, redis and vnc within 10 minutes
- **THEN** no scan classification occurs and no scan entry is stored

#### Scenario: IPv4-mapped IPv6
- **WHEN** the peer is `::ffff:8.8.8.8` and `8.8.8.8` is listed
- **THEN** the source is ignored

### Requirement: Limits still apply
Ignored sources SHALL count against `RAN_MAX_SESSIONS` and `RAN_MAX_PER_IP`.

#### Scenario: Flood from an ignored source
- **WHEN** an ignored IP opens more than `RAN_MAX_PER_IP` concurrent sessions
- **THEN** the excess sessions are rejected like any other source
