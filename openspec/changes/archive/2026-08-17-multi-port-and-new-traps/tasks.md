## 1. Config: Multi-Port Address Support

- [x] 1.1 Add `adb` (`:5555`) and `minecraft` (`:25565`) to `DefaultPorts` and `ValidTraps` in `internal/config/config.go`
- [x] 1.2 Add `TrapAddrs(name string) []string` method to `Config` that splits the stored address on commas and trims whitespace
- [x] 1.3 Add unit tests for `TrapAddrs` — single address, multiple addresses, whitespace handling
- [x] 1.4 Update config tests to cover ADB and Minecraft trap validation

## 2. MultiListener Infrastructure

- [x] 2.1 Implement `MultiListener` type in `internal/trap/trap.go` — struct with `[]net.Listener`, shared `chan net.Conn`, `Accept()`, `Close()`, `Addr()`
- [x] 2.2 Implement `ListenMultiTCP(ctx, addrs []string, proxyProto bool) (*MultiListener, error)` replacing `ListenTCP`
- [x] 2.3 Add `ConnContextWithDestPort` function and `DestPortFromContext` helper with context key in `internal/trap/trap.go`
- [x] 2.4 Remove old `ListenTCP` function (all callers will be migrated in task group 4)
- [x] 2.5 Add unit tests for `MultiListener` — single listener, multi listener, close behavior, Addr() return value
- [x] 2.6 Add unit tests for `ConnContextWithDestPort` and `DestPortFromContext`

## 3. UDP Multi-Port Support

- [x] 3.1 Change `UDPTrap` to accept `addrs []string` instead of single `addr string`, remove stored `destPort` field
- [x] 3.2 Update `UDPTrap.Start()` to open multiple `PacketConn` instances, each with its own read goroutine, deriving destPort from conn local address per packet
- [x] 3.3 Update `UDPTrap.Stop()` to close all `PacketConn` instances
- [x] 3.4 Update `NewUDP` signature and all 4 UDP trap factories (dns, snmp, sip, ntp) to pass `cfg.TrapAddrs(name)`
- [x] 3.5 Update UDP trap tests to cover multi-port behavior

## 4. Migrate Existing TCP Traps to MultiListener

- [x] 4.1 Migrate raw TCP traps to use `ListenMultiTCP(ctx, cfg.TrapAddrs(name), ...)` and `conn.LocalAddr()` for destPort: ssh, mysql, ftp, telnet, rdp, vnc, mqtt, modbus, ldap, smb, socks5, postgres, mssql, oracle, redis, memcached, pop3, imap, irc, smtp
- [x] 4.2 Migrate HTTP trap: use `ListenMultiTCP`, add `ConnContext: ConnContextWithDestPort` to `http.Server`, change `connState` to use `DestPortFromContext` or `conn.LocalAddr()`, change handlers if needed
- [x] 4.3 Migrate HTTPProxy trap: use `ListenMultiTCP`, add `ConnContext: ConnContextWithDestPort`, change `ServeHTTP` to use `DestPortFromContext(r.Context())`
- [x] 4.4 Migrate Elasticsearch trap: use `ListenMultiTCP`, add `ConnContext: ConnContextWithDestPort`, change `withSession` to use `DestPortFromContext(r.Context())`
- [x] 4.5 Update startup log messages to show all bound addresses (list instead of single addr)
- [x] 4.6 Verify all existing trap tests still pass with MultiListener (single-address backward compat)

## 5. New Traps

- [x] 5.1 Implement ADB trap in `internal/trap/adb.go` — CNXN parsing, AUTH response, session logging, alerting
- [x] 5.2 Register ADB trap in `internal/trap/registry.go`
- [x] 5.3 Add unit tests for ADB trap — valid CNXN, malformed data, timeout
- [x] 5.4 Implement Minecraft trap in `internal/trap/minecraft.go` — handshake parsing, varint decoding, status response, login extraction, disconnect
- [x] 5.5 Register Minecraft trap in `internal/trap/registry.go`
- [x] 5.6 Add unit tests for Minecraft trap — status ping flow, login flow, malformed handshake, timeout

## 6. Integration & Verification

- [x] 6.1 Add integration test: single trap on multiple ports, verify destPort logged correctly per connection
- [x] 6.2 Verify Docker/container config still works (update docker-compose if trap list examples exist)
- [x] 6.3 Update README or docs with multi-port config examples and new trap names
- [x] 6.4 Run full test suite, verify no regressions
