## Purpose

MSSQL honeypot trap that simulates a Microsoft SQL Server TDS endpoint to capture unauthorized access attempts.

## Requirements

### Requirement: MSSQL TDS credential capture
The MSSQL trap SHALL listen on TCP, handle the TDS prelogin handshake, accept a TDS Login7 packet, extract credentials, log them, and respond with a TDS error token.

#### Scenario: Login7 credential capture
- **WHEN** a client sends a TDS prelogin followed by Login7 with username="sa" and password="Password1"
- **THEN** the trap SHALL log auth_attempt with those credentials, alert CrowdSec, and respond with a TDS error message "Login failed for user 'sa'"

#### Scenario: Prelogin handshake
- **WHEN** a client sends a TDS prelogin request
- **THEN** the trap SHALL respond with a valid prelogin response indicating version and encryption support
