## Purpose

SIP honeypot trap that simulates a SIP server to capture unauthorized REGISTER and INVITE requests used in VoIP reconnaissance and toll fraud.

## Requirements

### Requirement: SIP REGISTER/INVITE capture
The SIP trap SHALL listen on UDP, parse SIP messages, log REGISTER and INVITE requests with From/To/Contact headers, and respond with 401 Unauthorized.

#### Scenario: REGISTER request
- **WHEN** a SIP REGISTER request arrives with From header containing a SIP URI
- **THEN** the trap SHALL log the From URI, To URI, Contact, and Call-ID, alert CrowdSec, and respond with `401 Unauthorized` including a WWW-Authenticate header

#### Scenario: INVITE request
- **WHEN** a SIP INVITE request arrives
- **THEN** the trap SHALL log the From/To URIs and SDP body (if present), and respond with `401 Unauthorized`

#### Scenario: Authorization header capture
- **WHEN** a subsequent request includes an Authorization header with digest credentials
- **THEN** the trap SHALL extract and log username, realm, nonce, and response hash
