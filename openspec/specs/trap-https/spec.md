# trap-https Specification

## Purpose
TBD - created by archiving change tls-traps. Update Purpose after archive.
## Requirements
### Requirement: TLS termination
The `https` trap SHALL terminate TLS with self-signed certificates (an ECDSA P-256 and an RSA-2048 one) and serve the HTTP trap handler on the decrypted stream. The certificates SHALL be generated on first start and persisted at `RAN_HTTPS_CERT_PATH` (one PEM file with both certificate and key pairs, written atomically with mode `0600`) when writable, otherwise ephemeral certificates SHALL be used and a warning logged. A persisted file that is unreadable, invalid, incomplete, expired or not yet valid SHALL be replaced. The trap SHALL accept old clients: minimum version TLS 1.0 and every cipher suite `crypto/tls` implements, with the certificate chosen by what the ClientHello supports. The handshake SHALL be bounded by the session timeout of the trap, and `Stop(ctx)` SHALL close connections that are still in the handshake as well as established ones.

#### Scenario: First start with writable data directory
- **WHEN** no certificate file exists and the directory is writable
- **THEN** a certificate is generated, persisted and reused on the next start

#### Scenario: Read-only data directory
- **WHEN** the directory is not writable
- **THEN** an ephemeral certificate is used and a warning is logged; startup does not fail

#### Scenario: Old and RSA-only clients
- **WHEN** a client offers only TLS 1.0, TLS 1.1 or RSA key exchange suites
- **THEN** the handshake completes and its HTTP request is recorded

#### Scenario: Idle client
- **WHEN** a client connects and sends nothing
- **THEN** the connection is closed after the session timeout

#### Scenario: Shutdown
- **WHEN** `Stop(ctx)` is called while TLS connections are open
- **THEN** all of them are closed and their limiter slots are released

### Requirement: ClientHello fingerprint
The trap SHALL record SNI, JA3 and JA4 of each ClientHello, with every list bounded, log them as a `tls client hello` event and add `sni`, `ja3` and `ja4` to the alert meta of the session. The values SHALL come from the first TLS record the client sends, which is captured with a size cap of 16389 bytes; extension order and GREASE values are read from the raw record because `tls.ClientHelloInfo` does not expose them. Lists SHALL be capped (256 cipher suites, 128 extensions, 64 groups, 16 point formats, 128 signature algorithms, 32 versions, 16 ALPN entries) and SNI SHALL be cut to 256 bytes with control characters replaced. A ClientHello that does not fit the first record SHALL get no JA3/JA4 (SNI is still recorded). Hellos that fail the handshake SHALL be fingerprinted as well.

#### Scenario: Scanner ClientHello
- **WHEN** a client sends a ClientHello with SNI `example.com`
- **THEN** the log and alert meta contain the SNI and both hashes

#### Scenario: GREASE
- **WHEN** a ClientHello carries GREASE cipher suites, extensions, groups or versions
- **THEN** they do not change JA3 or JA4

#### Scenario: Malformed ClientHello
- **WHEN** a client sends bytes that are not a TLS record
- **THEN** the session ends as a probe (class `probe`), no panic, bounded memory

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

