## ADDED Requirements

### Requirement: PostgreSQL credential capture
The PostgreSQL trap SHALL listen on TCP, accept StartupMessage, respond with AuthenticationCleartextPassword, capture the PasswordMessage, log credentials, and respond with ErrorResponse (FATAL: password authentication failed).

#### Scenario: Cleartext password capture
- **WHEN** a client sends a StartupMessage with user="postgres" and then a PasswordMessage with password="secret"
- **THEN** the trap SHALL log auth_attempt with username="postgres" and password="secret", alert CrowdSec, and send an ErrorResponse

#### Scenario: SSL negotiation
- **WHEN** a client sends an SSLRequest
- **THEN** the trap SHALL respond with 'N' (SSL not supported) and continue with plaintext startup
