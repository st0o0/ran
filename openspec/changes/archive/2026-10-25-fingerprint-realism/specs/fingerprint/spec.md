## ADDED Requirements

### Requirement: Seeded banner profiles
With `RAN_FINGERPRINT=seeded` (the default) the traps SHALL select version strings from built-in sets using a seed that is generated once and persisted, so the same instance presents the same banners after a restart. The selection SHALL be a deterministic function of the seed and the trap name, SHALL never vary per connection, and each selected entry SHALL be internally consistent (for example the `Server` header, the PHP version and the `/server-status` page of one HTTP entry).

#### Scenario: Restart
- **WHEN** the instance restarts with the same data volume
- **THEN** the SSH, MySQL and HTTP banners are unchanged

#### Scenario: Different instances
- **WHEN** two instances start with different seeds
- **THEN** their banners differ with high probability and every table value is reachable from some seed

#### Scenario: Read-only data directory
- **WHEN** the seed cannot be persisted
- **THEN** an ephemeral seed is used and a warning is logged

#### Scenario: Unusable seed file
- **WHEN** the seed file is unreadable, corrupt or shorter than 32 bytes
- **THEN** a warning is logged and a new seed is generated and persisted atomically with mode `0600`

#### Scenario: HTTP header parity
- **WHEN** the `http` trap, the `https` trap and the built-in fixtures answer
- **THEN** the `Server` and `X-Powered-By` headers are identical across them and the fixtures that name the server or PHP version (`/server-status`, `/phpinfo.php`) use the same profile entry

#### Scenario: Invalid mode
- **WHEN** `RAN_FINGERPRINT` is neither `seeded` nor `fixed`
- **THEN** the configuration is rejected with an error that names `RAN_FINGERPRINT`

### Requirement: Fixed mode
With `RAN_FINGERPRINT=fixed` the traps SHALL use the fixed banner values of earlier releases and SHALL NOT read or write the seed file.

#### Scenario: Fixed
- **WHEN** `RAN_FINGERPRINT=fixed`
- **THEN** the SSH banner is `SSH-2.0-OpenSSH_9.6`, the MySQL version `8.0.36`, the HTTP `Server` header `Apache/2.4.62` and the SMTP greeting `220 mx.localdomain ESMTP ready`

### Requirement: Per-trap class meta
Single-request traps without class describing meta (`vnc`, `rdp`, `oracle`, `mqtt`, `modbus`, `minecraft`, `adb`) SHALL add a fixed `kind` key to the alert meta describing what was seen. The values form a closed vocabulary per trap and never contain client data.

#### Scenario: VNC challenge response
- **WHEN** a VNC client completes the authentication exchange
- **THEN** the alert meta contains `kind=auth_response`

#### Scenario: Other traps
- **WHEN** an alert is raised by one of these traps
- **THEN** `kind` is one of `connection_request` (rdp), `connect` (oracle, mqtt, adb), `write` or `unknown_function` (modbus), `status`, `login` or `handshake` (minecraft), `auth` or `shell_command` (adb)
