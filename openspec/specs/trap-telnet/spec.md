## Purpose

Telnet honeypot trap that simulates a Telnet login service to capture unauthorized access attempts and credential harvesting.

## Requirements

### Requirement: Telnet login prompt and credential capture
The Telnet trap SHALL listen on TCP, present a login prompt, capture username and password, log the credentials, and display "Login incorrect".

#### Scenario: Credential capture
- **WHEN** a client connects and provides username "root" and password "toor"
- **THEN** the trap SHALL log an auth_attempt with those credentials, alert CrowdSec, and display "Login incorrect"

#### Scenario: Banner display
- **WHEN** a client connects
- **THEN** the trap SHALL send a system banner (e.g., hostname/OS identification) followed by a `login:` prompt
