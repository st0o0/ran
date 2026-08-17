## ADDED Requirements

### Requirement: Minecraft handshake parsing
The Minecraft trap SHALL accept TCP connections and read a Minecraft handshake packet: varint packet length, packet ID (0x00), varint protocol version, string server address, unsigned short server port, and varint next state (1=Status, 2=Login).

#### Scenario: Valid handshake with status intent
- **WHEN** a client sends a handshake with protocol version 767, server address `mc.example.com`, port 25565, and next state 1 (Status)
- **THEN** the trap parses and logs the protocol version, server address, and port

#### Scenario: Malformed handshake
- **WHEN** a client sends fewer bytes than a valid handshake or an invalid varint
- **THEN** the trap logs the raw bytes received (up to 256 bytes) and closes the connection

### Requirement: Status response
When the handshake next state is 1 (Status) and the client sends a Status Request packet (packet ID 0x00), the trap SHALL respond with a Status Response containing a JSON payload with server description, version info, and player count (0 of max 20).

#### Scenario: Status ping flow
- **WHEN** a client sends a handshake (next state 1) followed by a Status Request
- **THEN** the trap responds with a Status Response JSON containing `{"version":{"name":"1.21.4","protocol":767},"players":{"max":20,"online":0},"description":{"text":"A Minecraft Server"}}`

#### Scenario: Ping packet
- **WHEN** a client sends a Ping packet (ID 0x01) with a long payload after Status Response
- **THEN** the trap echoes the Ping as a Pong response

### Requirement: Login extraction
When the handshake next state is 2 (Login), the trap SHALL read the Login Start packet to extract the player name (string) and optional player UUID. It SHALL then send a Disconnect packet (ID 0x00) with a JSON text reason.

#### Scenario: Login attempt
- **WHEN** a client sends a handshake (next state 2) followed by Login Start with player name `Steve`
- **THEN** the trap logs the player name, sends a Disconnect with reason `{"text":"Server is under maintenance"}`, and closes

### Requirement: Session logging
Each Minecraft connection SHALL be logged with protocol `minecraft`, session_id, source_ip, source_port, dest_port, and action (connect, payload, disconnect). Handshake data SHALL be logged as a `payload` event with type `mc_handshake`. Login player names SHALL be logged as type `mc_login`.

#### Scenario: Status scan log
- **WHEN** a scanner connects and performs a status ping
- **THEN** log entries include: connect, payload (mc_handshake with protocol version and server address), disconnect

#### Scenario: Login attempt log
- **WHEN** a client connects and attempts login as `Steve`
- **THEN** log entries include: connect, payload (mc_handshake), payload (mc_login with player_name `Steve`), disconnect

### Requirement: CrowdSec alert
The Minecraft trap SHALL call `alerter.Alert()` with protocol `minecraft` and metadata containing the protocol version and player name (if Login flow) on every connection that sends a valid handshake.

#### Scenario: Alert on status scan
- **WHEN** a scanner performs a status ping with protocol version 767
- **THEN** `alerter.Alert(ctx, ip, "minecraft", {"protocol_version": "767", "server_address": "mc.example.com"})` is called

#### Scenario: Alert on login attempt
- **WHEN** a client attempts login as `Steve`
- **THEN** `alerter.Alert(ctx, ip, "minecraft", {"protocol_version": "767", "player_name": "Steve"})` is called

### Requirement: Default listen address
The Minecraft trap SHALL listen on `:25565` by default, configurable via `RAN_MINECRAFT_ADDR`.

#### Scenario: Default port
- **WHEN** `RAN_MINECRAFT_ADDR` is not set
- **THEN** the trap listens on port 25565

### Requirement: Session timeout
Minecraft connections SHALL be closed after `RAN_SESSION_TIMEOUT` (default 30s) regardless of client activity.

#### Scenario: Idle connection
- **WHEN** a client connects but sends no data for 30 seconds
- **THEN** the connection is closed and a disconnect event is logged
