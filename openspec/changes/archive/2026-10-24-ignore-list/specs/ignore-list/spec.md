## ADDED Requirements

### Requirement: Ignore list configuration
`RAN_IGNORE_IPS` SHALL accept a comma-separated list of IP addresses and CIDR ranges (IPv4 and IPv6). Empty entries and surrounding whitespace SHALL be skipped, IPv4-mapped IPv6 entries SHALL be treated as IPv4 and duplicates SHALL be counted once. An invalid entry SHALL make the configuration invalid and the error SHALL name the entry. More than 1024 distinct entries SHALL make the configuration invalid and the error SHALL name the limit. A range with a prefix length below 8 bits (for example `0.0.0.0/0` or `::/0`) SHALL be accepted, SHALL be logged as a warning at startup and SHALL be printed as a warning on stderr by `ran check-config`.

#### Scenario: Valid list
- **WHEN** `RAN_IGNORE_IPS=8.8.8.8,1.1.1.0/24,2606:4700:4700::1111`
- **THEN** the configuration loads and the startup log reports 3 ignored ranges

#### Scenario: Whitespace, empty entries and duplicates
- **WHEN** `RAN_IGNORE_IPS= 8.8.8.8 ,, ::ffff:8.8.8.8,`
- **THEN** the configuration loads with one ignored range

#### Scenario: Invalid entry
- **WHEN** `RAN_IGNORE_IPS=8.8.8.8,not-an-ip`
- **THEN** `ran check-config` exits 1 and names `not-an-ip`

#### Scenario: Too many entries
- **WHEN** `RAN_IGNORE_IPS` holds 1025 distinct entries
- **THEN** `ran check-config` exits 1 and names the limit 1024

#### Scenario: Very wide range
- **WHEN** `RAN_IGNORE_IPS=0.0.0.0/0`
- **THEN** the configuration loads, the startup log carries a warning naming the range and `ran check-config` prints the same warning on stderr

### Requirement: Suppressed alerting
Sessions whose source is in the ignore list SHALL NOT raise alerts, SHALL NOT be recorded by the scan tracker and SHALL NOT be recorded in the probe summary. They SHALL still be served and logged with an `ignored=true` marker, and SHALL be counted in the connection metrics and in `ran_ignored_sessions_total{protocol}`. Ignored events SHALL never reach the CrowdSec sink, so no CrowdSec pipeline stage exists for them.

#### Scenario: Ignored attacker
- **WHEN** an ignored IP makes an SSH password attempt
- **THEN** the attempt is logged with `ignored=true`, no alert is queued and `ran_ignored_sessions_total{protocol="ssh"}` increases

#### Scenario: Scan state
- **WHEN** an ignored IP touches ssh, redis and vnc within 10 minutes
- **THEN** no scan classification occurs and no scan entry is stored

#### Scenario: Probe summary
- **WHEN** an ignored IP only connects to a trap
- **THEN** no probe summary entry is stored and the session keeps its per-session log lines

#### Scenario: Neighbor outside the list
- **WHEN** a source that is not listed attacks while an ignored source is active
- **THEN** the neighbor is classified, tracked and alerted as usual

#### Scenario: IPv4-mapped IPv6
- **WHEN** the peer is `::ffff:8.8.8.8` and `8.8.8.8` is listed
- **THEN** the source is ignored

#### Scenario: PROXY protocol
- **WHEN** `RAN_PROXY_PROTOCOL` is on and the PROXY header names a listed address
- **THEN** the session is ignored

#### Scenario: UDP trap
- **WHEN** an ignored IP sends a packet to a UDP trap
- **THEN** the session log lines carry `ignored=true` and `ran_ignored_sessions_total` increases (UDP never alerts)

### Requirement: Limits still apply
Ignored sources SHALL count against `RAN_MAX_SESSIONS` and `RAN_MAX_PER_IP`.

#### Scenario: Flood from an ignored source
- **WHEN** an ignored IP opens more than `RAN_MAX_PER_IP` concurrent sessions
- **THEN** the excess sessions are rejected like any other source
