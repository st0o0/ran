## 1. Foundation

- [x] 1.1 Extend Session with LogCommand and LogPayload methods in trap.go
- [x] 1.2 Refactor config.go: add RAN_TRAPS list, default port map, EnabledTraps(), per-trap addr fields
- [x] 1.3 Add trap registry map and refactor run.go to use registry-based startup
- [x] 1.4 Create UDP listener helper in udp.go

## 2. Simple Text Protocol Traps (TCP)

- [x] 2.1 FTP trap (ftp.go + ftp_test.go)
- [x] 2.2 Telnet trap (telnet.go + telnet_test.go)
- [x] 2.3 Redis trap (redis.go + redis_test.go)
- [x] 2.4 Memcached trap (memcached.go + memcached_test.go)
- [x] 2.5 POP3 trap (pop3.go + pop3_test.go)
- [x] 2.6 IMAP trap (imap.go + imap_test.go)
- [x] 2.7 IRC trap (irc.go + irc_test.go)

## 3. SMTP and Mail Traps

- [x] 3.1 SMTP trap (smtp.go + smtp_test.go)

## 4. Database Protocol Traps

- [x] 4.1 PostgreSQL trap (postgres.go + postgres_test.go)
- [x] 4.2 MSSQL trap (mssql.go + mssql_test.go)
- [x] 4.3 Oracle TNS trap (oracle.go + oracle_test.go)

## 5. Directory and Network Service Traps

- [x] 5.1 LDAP trap (ldap.go + ldap_test.go)
- [x] 5.2 SMB trap (smb.go + smb_test.go)
- [x] 5.3 SOCKS5 trap (socks5.go + socks5_test.go)

## 6. Remote Access Traps

- [x] 6.1 RDP trap (rdp.go + rdp_test.go)
- [x] 6.2 VNC trap (vnc.go + vnc_test.go)

## 7. HTTP-Based Traps

- [x] 7.1 Elasticsearch trap (elasticsearch.go + elasticsearch_test.go)
- [x] 7.2 HTTP Proxy trap (httpproxy.go + httpproxy_test.go)

## 8. IoT / Industrial Traps

- [x] 8.1 MQTT trap (mqtt.go + mqtt_test.go)
- [x] 8.2 Modbus trap (modbus.go + modbus_test.go)

## 9. UDP Traps

- [x] 9.1 DNS trap (dns.go + dns_test.go)
- [x] 9.2 SNMP trap (snmp.go + snmp_test.go)
- [x] 9.3 SIP trap (sip.go + sip_test.go)
- [x] 9.4 NTP trap (ntp.go + ntp_test.go)

## 10. Integration

- [x] 10.1 Register all new traps in the registry map
- [x] 10.2 Update Dockerfile to expose new ports
- [x] 10.3 Update README.md with new trap documentation and configuration
- [x] 10.4 Run full test suite and fix any issues
