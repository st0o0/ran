## ADDED Requirements

### Requirement: MongoDB wire protocol stub
The `mongodb` trap SHALL parse `OP_MSG` and legacy `OP_QUERY` messages and answer `hello`/`isMaster`, `buildInfo` and `ping` with plausible documents (an `OP_MSG` reply to `OP_MSG`, an `OP_REPLY` to `OP_QUERY`). It SHALL run on the shared TCP skeleton. A message with `moreToCome` set SHALL get no reply.

#### Scenario: Hello
- **WHEN** a client sends an `OP_MSG` containing `hello`
- **THEN** a valid reply is returned and the session stays a `probe`

### Requirement: Bounded message reader
The declared message length SHALL be checked against a limit of 64 KiB before any body is read, using `fitsInt` for the 32-bit field. A length above the limit or below the 16 byte header, a malformed BSON document, an unknown required `OP_MSG` flag bit or an unknown section kind SHALL close the connection. Only the first 64 top-level elements of the command document SHALL be walked; nested documents and arrays SHALL be skipped by their declared length and never entered. An unsupported opcode with a well-formed header SHALL close the connection and count its bytes as payload.

#### Scenario: Oversized message
- **WHEN** the message header declares a length above the limit
- **THEN** the connection is closed without allocating that length

#### Scenario: Malformed document
- **WHEN** an element declares a length that exceeds the document
- **THEN** the connection is closed and no command is recorded

### Requirement: Authentication required
Commands other than the handshake commands (`hello`, `isMaster`, `buildInfo`, `ping`) SHALL be answered with an `Unauthorized` error (code 13). `saslStart` and `authenticate` SHALL be recorded as auth attempts with the username (and the mechanism) only and answered with `AuthenticationFailed` (code 18). SASL proofs, nonces and passwords SHALL NOT be logged or sent as alert meta.

#### Scenario: listDatabases
- **WHEN** a client sends `listDatabases`
- **THEN** the command name is recorded, an `Unauthorized` error is returned and the session is `attack`

#### Scenario: SCRAM start
- **WHEN** a client sends `saslStart` with user `admin`
- **THEN** an auth attempt for `admin` is logged without any proof or password data in alert meta

#### Scenario: PLAIN start
- **WHEN** a client sends `saslStart` with a PLAIN payload for user `root`
- **THEN** only `root` is recorded and the password never appears in logs or alert meta
