## MODIFIED Requirements

### Requirement: Per-trap address configuration
For each trap, the system SHALL accept a `RAN_<PROTO>_ADDR` environment variable to override the default listen address. The value MAY contain multiple comma-separated addresses (e.g. `:8081,:8080,:8443`). The system SHALL store the raw value in `Config.Addrs[name]`. A new `TrapAddrs(name) []string` method SHALL split the stored value on commas, trim whitespace from each segment, and return the list. `TrapAddr(name) string` SHALL continue to return the raw stored string for backward compatibility.

#### Scenario: Single address (backward compatible)
- **WHEN** `RAN_SSH_ADDR=:2200` is set
- **THEN** `TrapAddr("ssh")` returns `:2200` and `TrapAddrs("ssh")` returns `[":2200"]`

#### Scenario: Multiple addresses
- **WHEN** `RAN_HTTP_ADDR=:8081,:8080,:8443` is set
- **THEN** `TrapAddr("http")` returns `:8081,:8080,:8443` and `TrapAddrs("http")` returns `[":8081", ":8080", ":8443"]`

#### Scenario: Whitespace in comma-separated list
- **WHEN** `RAN_HTTP_ADDR=:8081, :8080 , :8443` is set
- **THEN** `TrapAddrs("http")` returns `[":8081", ":8080", ":8443"]` with whitespace trimmed

#### Scenario: All new traps have default addresses
- **WHEN** a trap is enabled without a corresponding `RAN_<PROTO>_ADDR`
- **THEN** the trap SHALL listen on its default port (FTP=:21, Telnet=:23, SMTP=:25, DNS=:53, POP3=:110, IMAP=:143, LDAP=:389, SMB=:445, Modbus=:502, SOCKS5=:1080, MSSQL=:1433, Oracle=:1521, MQTT=:1883, RDP=:3389, PostgreSQL=:5432, SIP=:5060, VNC=:5900, Redis=:6379, IRC=:6667, HTTP Proxy=:8080, Elasticsearch=:9200, Memcached=:11211, NTP=:123, SNMP=:161, ADB=:5555, Minecraft=:25565)

## ADDED Requirements

### Requirement: ADB and Minecraft in DefaultPorts and ValidTraps
The `DefaultPorts` map SHALL include entries for `adb` (`:5555`) and `minecraft` (`:25565`). The `ValidTraps` set SHALL include `adb` and `minecraft` as valid trap names for `RAN_TRAPS`.

#### Scenario: Enable ADB trap
- **WHEN** `RAN_TRAPS=adb` is set
- **THEN** the system SHALL start the ADB trap on its default port :5555

#### Scenario: Enable Minecraft trap
- **WHEN** `RAN_TRAPS=minecraft` is set
- **THEN** the system SHALL start the Minecraft trap on its default port :25565

#### Scenario: Unknown trap rejected
- **WHEN** `RAN_TRAPS=unknowntrap` is set
- **THEN** config loading returns an error listing valid trap names including `adb` and `minecraft`
