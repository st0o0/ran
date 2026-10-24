## ADDED Requirements

### Requirement: MongoDB wire protocol stub
The `mongodb` trap SHALL parse `OP_MSG` and legacy `OP_QUERY` messages with a bounded message length and answer `hello`/`isMaster` and `buildInfo` with plausible documents.

#### Scenario: Hello
- **WHEN** a client sends an `OP_MSG` containing `hello`
- **THEN** a valid reply is returned and the session stays a `probe`

#### Scenario: Oversized message
- **WHEN** the message header declares a length above the limit
- **THEN** the connection is closed without allocating that length

### Requirement: Authentication required
Commands other than the handshake commands SHALL be answered with an `Unauthorized` error. `saslStart` and `authenticate` SHALL be recorded as auth attempts with the username only.

#### Scenario: listDatabases
- **WHEN** a client sends `listDatabases`
- **THEN** the command name is recorded, an `Unauthorized` error is returned and the session is `attack`

#### Scenario: SCRAM start
- **WHEN** a client sends `saslStart` with user `admin`
- **THEN** an auth attempt for `admin` is logged without any proof or password data in alert meta
