## ADDED Requirements

### Requirement: RDP connection capture
The RDP trap SHALL listen on TCP, accept an X.224 Connection Request, log the requested cookie/username, and respond with a Connection Confirm followed by a negotiation failure.

#### Scenario: X.224 connection request with cookie
- **WHEN** a client sends an X.224 CR with cookie "Cookie: mstshash=administrator"
- **THEN** the trap SHALL log the connection with username="administrator" extracted from the cookie, alert CrowdSec, and respond with X.224 CC then RDP Negotiation Failure

#### Scenario: X.224 connection request without cookie
- **WHEN** a client sends an X.224 CR without a cookie
- **THEN** the trap SHALL log the connection with an empty username and respond with X.224 CC then RDP Negotiation Failure
