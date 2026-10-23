## Purpose

README guidance and example CrowdSec profiles for the sensor model, where ran pushes decision-less alerts and profiles decide about bans.

## Requirements

### Requirement: Sensor escalation documentation
The README SHALL explain that ran pushes decision-less alerts and CrowdSec profiles decide bans, include an example `profiles.yaml` keyed by `class` (attack: 1h base, key `filters:` as a list (the singular `filter:` is rejected by CrowdSec v1.8.1), escalating with `Sprintf('%.0fh', min(168.0, 3 ^ GetDecisionsCount(Alert.GetValue())))`, lowercase `min` and `%.0fh`; scan: the same formula, with a note that operators may use a harder one; probe: no profile), and replace the 0.3.x "Ban Escalation" section.

#### Scenario: Example profiles
- **WHEN** a reader opens the CrowdSec section
- **THEN** it contains profiles using the list key `filters:` with `Alert.GetScenario() startsWith "custom/ran-" && Alert.Events[0].GetMeta("class") == "attack"` (same for scan), and states that probe is never banned

#### Scenario: Escalation expression
- **WHEN** the example attack profile is read
- **THEN** its `duration_expr` is `Sprintf('%.0fh', min(168.0, 3 ^ GetDecisionsCount(Alert.GetValue())))` and the README warns that `Min` fails fatally and `%dh` silently falls back to the base duration

#### Scenario: Old claim removed
- **WHEN** the README is searched for "embedded default decision applies"
- **THEN** no match exists

### Requirement: CrowdSec behavior notes
The README SHALL state that decision-less alerts are still shared to CAPI unless `simulated: true`, that allowlists apply to them, that machine credentials remain required, that `db_config.flush.max_age` and `max_items` affect `GetDecisionsCount`, and that no profile means no ban. It SHALL also state that alert history bounds escalation memory: `db_config.flush.max_items` deletes alerts without an active decision, lowering the escalation level, so operators must size `max_items` and `max_age` to cover 168h at their alert rate (ran created about 4000 alerts per day before the cooldown design).

#### Scenario: Flush sizing note
- **WHEN** an operator reads the CrowdSec behavior notes
- **THEN** they find the `max_items` and `max_age` sizing guidance and that active bans are never expired early

#### Scenario: Migration note
- **WHEN** an operator upgrades from 0.3.x
- **THEN** the README lists removed variables and the required profile step
