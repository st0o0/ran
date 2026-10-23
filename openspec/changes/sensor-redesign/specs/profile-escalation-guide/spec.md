## ADDED Requirements

### Requirement: Sensor escalation documentation
The README SHALL explain that ran pushes decision-less alerts and CrowdSec profiles decide bans, include an example `profiles.yaml` keyed by `class` (attack: 4h base escalating with `3^GetDecisionsCount` capped at 168h; scan: longer base; probe: no profile), and replace the 0.3.x "Ban Escalation" section.

#### Scenario: Example profiles
- **WHEN** a reader opens the CrowdSec section
- **THEN** it contains profiles filtering on `Alert.Events[0].GetMeta("class")` for attack and scan, and states that probe is never banned

#### Scenario: Old claim removed
- **WHEN** the README is searched for "embedded default decision applies"
- **THEN** no match exists

### Requirement: CrowdSec behavior notes
The README SHALL state that decision-less alerts are still shared to CAPI unless `simulated: true`, that allowlists apply to them, that machine credentials remain required, that `db_config.flush.max_age` and `max_items` affect `GetDecisionsCount`, and that no profile means no ban.

#### Scenario: Migration note
- **WHEN** an operator upgrades from 0.3.x
- **THEN** the README lists removed variables and the required profile step
