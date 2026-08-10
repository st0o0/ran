## Why

ran currently covers only 3 protocols (SSH, HTTP, MySQL), missing the vast majority of services that attackers actively scan. Projects like T-Pot (31 honeypots) and qeeqbox/honeypots (30 protocols) demonstrate that broad protocol coverage is essential for meaningful threat intelligence. Adding 24 more traps makes ran a comprehensive single-binary honeypot that captures credential stuffing, amplification probes, proxy abuse, and ICS reconnaissance — all without external dependencies.

## What Changes

- Add 20 new TCP-based traps: FTP, Telnet, SMTP, POP3, IMAP, LDAP, SMB, SOCKS5, MSSQL, Oracle/TNS, PostgreSQL, Redis, RDP, VNC, Memcached, Elasticsearch, IRC, MQTT, Modbus, HTTP Proxy
- Add 4 new UDP-based traps: DNS, SNMP, SIP, NTP
- Add UDP listener base pattern (`net.ListenPacket`) alongside existing TCP pattern
- Refactor config to support `RAN_TRAPS=ssh,ftp,telnet,...` list-style enabling (keep per-trap `RAN_<PROTO>=on` as fallback)
- Extend Session with `LogCommand` and `LogPayload` for traps that capture commands/queries rather than credentials
- Add default port mapping so each trap has a sensible default address
- Update metrics labels for all new protocols
- Update Dockerfile to expose new ports

## Capabilities

### New Capabilities
- `trap-ftp`: FTP credential-capture trap (port 21)
- `trap-telnet`: Telnet credential-capture trap (port 23)
- `trap-smtp`: SMTP relay-probe and credential-capture trap (port 25)
- `trap-dns`: DNS query logging and amplification detection trap (port 53/udp)
- `trap-pop3`: POP3 credential-capture trap (port 110)
- `trap-imap`: IMAP credential-capture trap (port 143)
- `trap-ldap`: LDAP bind/search enumeration trap (port 389)
- `trap-smb`: SMB negotiate/session-setup trap (port 445)
- `trap-socks5`: SOCKS5 open-proxy abuse detection trap (port 1080)
- `trap-mssql`: MSSQL TDS credential-capture trap (port 1433)
- `trap-oracle`: Oracle TNS credential-capture trap (port 1521)
- `trap-postgres`: PostgreSQL credential-capture trap (port 5432)
- `trap-redis`: Redis command logging trap (port 6379)
- `trap-rdp`: RDP connection/credential-capture trap (port 3389)
- `trap-vnc`: VNC authentication-capture trap (port 5900)
- `trap-memcached`: Memcached command logging trap (port 11211)
- `trap-elasticsearch`: Elasticsearch HTTP API trap (port 9200)
- `trap-sip`: SIP VoIP fraud detection trap (port 5060/udp)
- `trap-snmp`: SNMP community-string capture trap (port 161/udp)
- `trap-ntp`: NTP amplification detection trap (port 123/udp)
- `trap-irc`: IRC C2-channel detection trap (port 6667)
- `trap-mqtt`: MQTT IoT credential-capture trap (port 1883)
- `trap-modbus`: Modbus ICS/SCADA reconnaissance trap (port 502)
- `trap-httpproxy`: HTTP proxy abuse detection trap (port 8080)
- `udp-trap-base`: UDP listener pattern for packet-based traps
- `config-traps-list`: Refactored config supporting RAN_TRAPS list and per-trap addr overrides

### Modified Capabilities
- `config`: Add trap list support, default port map, per-trap addr overrides
- `lifecycle`: Register new traps in run.go startup sequence

## Impact

- `internal/trap/` — 24 new files, ~2500 LOC total
- `internal/trap/trap.go` — extended Session type with LogCommand/LogPayload
- `internal/trap/udp.go` — new UDP base pattern
- `internal/config/config.go` — refactored trap enabling + new addr fields
- `cmd/ran/run.go` — register all new traps
- `Dockerfile` — expose additional ports
- `go.mod` — may add `golang.org/x/crypto` (already present), no other external deps expected
- `README.md` — document new traps and configuration
