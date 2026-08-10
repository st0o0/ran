## MODIFIED Requirements

### Requirement: CrowdSec alert on auth attempt
The SSH trap SHALL call `alerter.Alert()` with the source IP and protocol `ssh` on every auth_attempt.

#### Scenario: SSH auth triggers alert
- **WHEN** an attacker attempts SSH password auth
- **THEN** `alerter.Alert(ctx, "1.2.3.4", "ssh")` is called
