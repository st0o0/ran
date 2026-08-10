## MODIFIED Requirements

### Requirement: Trap enabling validation
The system SHALL validate that at least one trap is enabled. If neither `RAN_TRAPS` nor any legacy `RAN_<PROTO>=on` variable is set, the system SHALL return an error.

#### Scenario: No traps enabled
- **WHEN** neither `RAN_TRAPS` nor any `RAN_SSH`/`RAN_HTTP`/`RAN_MYSQL` variable is set
- **THEN** the system SHALL return an error "at least one trap must be enabled"

#### Scenario: RAN_TRAPS enables traps
- **WHEN** `RAN_TRAPS=ftp,redis` is set
- **THEN** the system SHALL start the FTP and Redis traps

## ADDED Requirements

### Requirement: Per-trap address configuration
For each new trap, the system SHALL accept a `RAN_<PROTO>_ADDR` environment variable to override the default listen address.

#### Scenario: All new traps have default addresses
- **WHEN** a trap is enabled without a corresponding `RAN_<PROTO>_ADDR`
- **THEN** the trap SHALL listen on its default port (FTP=:21, Telnet=:23, SMTP=:25, DNS=:53, POP3=:110, IMAP=:143, LDAP=:389, SMB=:445, Modbus=:502, SOCKS5=:1080, MSSQL=:1433, Oracle=:1521, MQTT=:1883, RDP=:3389, PostgreSQL=:5432, SIP=:5060, VNC=:5900, Redis=:6379, IRC=:6667, HTTP Proxy=:8080, Elasticsearch=:9200, Memcached=:11211, NTP=:123, SNMP=:161)
