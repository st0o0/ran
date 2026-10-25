# fingerprint Specification

## Purpose
Vary the version strings the traps present (SSH identification, MySQL server version and greeting, Apache or nginx `Server` and PHP versions, SMTP greeting, Elasticsearch root document) per instance, so a fleet of sensors is not recognizable by one fixed set of banners, while each instance stays stable across restarts. Also defines the per-trap `kind` alert meta of the single-request traps and the `fixed` mode that keeps the original values.
## Requirements
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


### Requirement: Stable selection
The entry a table yields for a seed SHALL depend on the seed and on the entry itself (a key derived from its values), not on its position, using HMAC-SHA256 scores (rendezvous hashing). A golden test SHALL pin the selected entries of every table for fixed seeds. Tables are append only: entries SHALL NOT be edited in place, renamed or removed, because that changes the banners of existing instances on upgrade.

#### Scenario: Reordered table
- **WHEN** the entries of a table are reordered
- **THEN** every seed still selects the same entry

#### Scenario: Appended entry
- **WHEN** an entry is appended to a table
- **THEN** only the instances that score the new entry highest (about one in n+1) change their banner

### Requirement: Era-consistent details
Seeded mode SHALL keep details that follow from a banner consistent with it. The `/phpinfo.php` fixture SHALL print the distribution package version of PHP and a kernel release that matches the distribution of the HTTP entry (while `X-Powered-By` carries the plain PHP version). The Elasticsearch root document SHALL carry `build_flavor`, `build_type`, `build_hash`, `build_date`, `build_snapshot`, `lucene_version`, `minimum_wire_compatibility_version`, `minimum_index_compatibility_version` and `tagline`, and the `X-elastic-product` header SHALL be sent only for versions 7.14 and later. Fixed mode SHALL keep the earlier `/phpinfo.php` text and the short root document.

#### Scenario: Elasticsearch 7.10
- **WHEN** the profile has Elasticsearch 7.10.2
- **THEN** the responses carry no `X-elastic-product` header and the root document reports Lucene 8.7.0
