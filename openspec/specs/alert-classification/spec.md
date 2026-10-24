## Purpose

Classification of honeypot sessions into probe, attack and scan, scan detection and aggregated logging of probe sessions.
## Requirements
### Requirement: Session classification
Each TCP trap session SHALL be classified as `attack` when it recorded at least one auth attempt, command or payload byte, otherwise as `probe` (connect and banner only).

#### Scenario: Credentials attempted
- **WHEN** a session logs an auth attempt
- **THEN** its class is `attack`

#### Scenario: Connect only
- **WHEN** a session connects, receives the banner and disconnects
- **THEN** its class is `probe`

### Requirement: Scan detection
A source IP that touches at least 3 distinct TCP trap protocols within 10 minutes SHALL be classified `scan`. UDP protocols SHALL NOT count. The tracking map SHALL be capped with oldest-first eviction.

#### Scenario: Three protocols
- **WHEN** 192.0.2.10 connects to ssh, redis and vnc within 10 minutes
- **THEN** the third session is classified `scan`

#### Scenario: UDP ignored
- **WHEN** an IP sends dns, snmp and ntp packets within 10 minutes
- **THEN** no scan classification occurs

#### Scenario: Window expiry
- **WHEN** the three protocols are touched over more than 10 minutes
- **THEN** the IP is not classified `scan`

#### Scenario: Map cap
- **WHEN** the tracking map reaches its cap
- **THEN** the oldest entries are evicted and memory stays bounded

### Requirement: Aggregated logging
Probe sessions SHALL be logged as one summary line per source IP and time window (sessions per protocol, totals) instead of per-session lines. Attack sessions SHALL keep full per-event lines. Metrics SHALL be updated per session regardless.

#### Scenario: Probe burst
- **WHEN** one IP opens 500 VNC connections without sending data in one window
- **THEN** one summary line is logged and `ran_connections_total{protocol="vnc"}` increases by 500

#### Scenario: Attack session
- **WHEN** a session captures credentials
- **THEN** the credential line is logged immediately

### Requirement: Scan detection by distinct ports
A source IP that touches at least 5 distinct destination ports of TCP traps within 10 minutes SHALL be classified `scan`, in addition to the existing distinct-protocol rule. UDP SHALL NOT count, sources in `RAN_IGNORE_IPS` SHALL NOT be tracked, and the tracking map SHALL stay capped. At most 16 ports SHALL be remembered per source.

#### Scenario: Multi-port HTTP
- **WHEN** one IP connects to the http trap on five different ports within 10 minutes
- **THEN** the fifth session is classified `scan`

#### Scenario: Same port repeated
- **WHEN** one IP connects to the same port 50 times
- **THEN** no port-based scan classification occurs

#### Scenario: Window expiry
- **WHEN** the ports are touched over more than 10 minutes so that fewer than five are live
- **THEN** no port-based scan classification occurs

#### Scenario: UDP and ignored sources
- **WHEN** a UDP source or an ignored source touches six different ports
- **THEN** nothing is tracked and no scan classification occurs

#### Scenario: Cap
- **WHEN** the tracker holds the maximum number of entries
- **THEN** the oldest entry is evicted and per-entry port sets stay bounded

