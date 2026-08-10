## MODIFIED Requirements

### Requirement: CrowdSec alert on credential capture
The HTTP trap SHALL call `alerter.Alert()` with the source IP and protocol `http` on every credential POST.

#### Scenario: HTTP credential POST triggers alert
- **WHEN** an attacker POSTs credentials to a login page
- **THEN** `alerter.Alert(ctx, "1.2.3.4", "http")` is called
