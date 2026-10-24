## ADDED Requirements

### Requirement: TLS termination
The `https` trap SHALL terminate TLS with a self-signed certificate and serve the HTTP trap handler on the decrypted stream. The certificate SHALL be generated on first start and persisted at `RAN_HTTPS_CERT_PATH` when writable, otherwise an ephemeral certificate SHALL be used and a warning logged.

#### Scenario: First start with writable data directory
- **WHEN** no certificate file exists and the directory is writable
- **THEN** a certificate is generated, persisted and reused on the next start

#### Scenario: Read-only data directory
- **WHEN** the directory is not writable
- **THEN** an ephemeral certificate is used and a warning is logged; startup does not fail

### Requirement: ClientHello fingerprint
The trap SHALL record SNI, JA3 and JA4 of each ClientHello, with every list bounded, and SHALL add `sni`, `ja3` and `ja4` to the alert meta of the session.

#### Scenario: Scanner ClientHello
- **WHEN** a client sends a ClientHello with SNI `example.com`
- **THEN** the log and alert meta contain the SNI and both hashes

#### Scenario: Malformed ClientHello
- **WHEN** a client sends bytes that are not a TLS record
- **THEN** the session ends as a probe with outcome `probe`, no panic, bounded memory

### Requirement: Classification
A TLS session that completes the handshake without sending an HTTP request SHALL be a `probe`. HTTP requests inside the tunnel SHALL be classified by the `trap-http` rules.

#### Scenario: Handshake only
- **WHEN** a client completes the handshake and closes
- **THEN** the session class is `probe`

#### Scenario: Exploit path over TLS
- **WHEN** a client requests `GET /.env` inside the tunnel
- **THEN** the session class is `attack`

### Requirement: Spoofing resistance
The alert IP SHALL be the socket peer, as for `http`.

#### Scenario: Forwarded header over TLS
- **WHEN** a request inside the tunnel carries `X-Forwarded-For`
- **THEN** it is logged as `claimed_client_ip` and does not change the alert IP
