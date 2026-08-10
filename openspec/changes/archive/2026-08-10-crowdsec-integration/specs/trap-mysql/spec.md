## MODIFIED Requirements

### Requirement: CrowdSec alert on auth attempt
The MySQL trap SHALL call `alerter.Alert()` with the source IP and protocol `mysql` on every auth_attempt.

#### Scenario: MySQL auth triggers alert
- **WHEN** an attacker completes the MySQL handshake
- **THEN** `alerter.Alert(ctx, "1.2.3.4", "mysql")` is called
