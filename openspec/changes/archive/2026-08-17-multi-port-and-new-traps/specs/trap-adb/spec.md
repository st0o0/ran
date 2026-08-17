## ADDED Requirements

### Requirement: ADB protocol emulation
The ADB trap SHALL accept TCP connections and read the 24-byte ADB message header. If the command field equals `CNXN` (0x4e584e43), the trap SHALL read the payload (system identity string) up to the data length specified in the header (capped at 4096 bytes).

#### Scenario: Valid CNXN message
- **WHEN** a client sends a valid ADB CNXN message with system identity `host::features=shell_v2`
- **THEN** the trap reads and logs the system identity string

#### Scenario: Non-CNXN or malformed data
- **WHEN** a client sends fewer than 24 bytes or a non-CNXN command
- **THEN** the trap logs the raw bytes received (up to 256 bytes) and closes the connection

### Requirement: AUTH token response
After receiving a CNXN message, the trap SHALL respond with an ADB AUTH message (command 0x48545541, type 1 = TOKEN) containing 20 random bytes as the token payload. The connection SHALL then be closed after a short read timeout to capture any follow-up data.

#### Scenario: AUTH response sent
- **WHEN** a valid CNXN message is received
- **THEN** the trap sends a 24-byte AUTH header plus 20-byte random token, then closes

### Requirement: Session logging
Each ADB connection SHALL be logged with protocol `adb`, session_id, source_ip, source_port, dest_port, and action (connect, payload, disconnect). The system identity from CNXN messages SHALL be logged as a `payload` event with type `adb_identity`.

#### Scenario: Full session log
- **WHEN** a client connects from 1.2.3.4:54321 and sends a CNXN with identity `host::`
- **THEN** three log entries are emitted: connect, payload (adb_identity with identity string), disconnect

### Requirement: CrowdSec alert
The ADB trap SHALL call `alerter.Alert()` with protocol `adb` and metadata containing the system identity string (if available) on every connection that sends a CNXN message.

#### Scenario: Alert with identity
- **WHEN** a client sends a CNXN with identity `host::features=shell_v2`
- **THEN** `alerter.Alert(ctx, ip, "adb", {"identity": "host::features=shell_v2"})` is called

### Requirement: Default listen address
The ADB trap SHALL listen on `:5555` by default, configurable via `RAN_ADB_ADDR`.

#### Scenario: Default port
- **WHEN** `RAN_ADB_ADDR` is not set
- **THEN** the trap listens on port 5555

### Requirement: Session timeout
ADB connections SHALL be closed after `RAN_SESSION_TIMEOUT` (default 30s) regardless of client activity.

#### Scenario: Idle connection
- **WHEN** a client connects but sends no data for 30 seconds
- **THEN** the connection is closed and a disconnect event is logged
