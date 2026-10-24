## ADDED Requirements

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
