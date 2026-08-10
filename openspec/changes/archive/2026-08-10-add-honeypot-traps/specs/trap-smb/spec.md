## ADDED Requirements

### Requirement: SMB negotiate and session setup capture
The SMB trap SHALL listen on TCP, handle SMB/SMB2 Negotiate, respond with a Negotiate response, accept Session Setup requests, log the authentication attempt, and respond with STATUS_LOGON_FAILURE.

#### Scenario: SMB2 session setup capture
- **WHEN** a client sends an SMB2 Negotiate followed by Session Setup with NTLMSSP authentication
- **THEN** the trap SHALL extract the domain, username, and workstation from the NTLMSSP message, log them as auth_attempt, alert CrowdSec, and respond with STATUS_LOGON_FAILURE

#### Scenario: SMB1 negotiate
- **WHEN** a client sends an SMB1 Negotiate
- **THEN** the trap SHALL respond with a valid SMB1 Negotiate response selecting NT LM 0.12 dialect

#### Scenario: SMB2 negotiate
- **WHEN** a client sends an SMB2 Negotiate
- **THEN** the trap SHALL respond selecting SMB 2.1 dialect with NTLMSSP security
