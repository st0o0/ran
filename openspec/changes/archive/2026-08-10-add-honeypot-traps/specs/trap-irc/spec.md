## ADDED Requirements

### Requirement: IRC nickname and command capture
The IRC trap SHALL listen on TCP, accept NICK/USER registration, send welcome numerics, log all commands received, and capture PASS credentials if sent.

#### Scenario: PASS credential capture
- **WHEN** a client sends `PASS secret` before NICK/USER
- **THEN** the trap SHALL log auth_attempt with password="secret" and alert CrowdSec

#### Scenario: NICK/USER registration
- **WHEN** a client sends `NICK bot1` and `USER bot1 0 * :Bot`
- **THEN** the trap SHALL log the registration with nickname="bot1" and respond with 001 RPL_WELCOME

#### Scenario: Command logging
- **WHEN** a client sends `JOIN #channel` or `PRIVMSG #channel :message`
- **THEN** the trap SHALL log the command with all arguments
