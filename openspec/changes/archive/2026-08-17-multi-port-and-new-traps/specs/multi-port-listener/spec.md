## ADDED Requirements

### Requirement: MultiListener wraps multiple TCP listeners
The system SHALL provide a `MultiListener` type implementing `net.Listener` that internally manages multiple `net.Listener` instances. Calling `Accept()` SHALL return connections from any of the wrapped listeners. Calling `Close()` SHALL close all wrapped listeners.

#### Scenario: Single address behaves like regular listener
- **WHEN** a `MultiListener` is created with one address `[":8081"]`
- **THEN** it opens one TCP listener and `Accept()` returns connections on port 8081

#### Scenario: Multiple addresses accept on all ports
- **WHEN** a `MultiListener` is created with addresses `[":8081", ":8080", ":8443"]`
- **THEN** it opens three TCP listeners and `Accept()` returns connections arriving on any of the three ports

#### Scenario: Connection carries correct local address
- **WHEN** a connection arrives on port 8443 of a multi-port listener
- **THEN** `conn.LocalAddr()` returns an address with port 8443

#### Scenario: Close stops all listeners
- **WHEN** `Close()` is called on a `MultiListener` with three internal listeners
- **THEN** all three listeners are closed and subsequent `Accept()` calls return an error

#### Scenario: Addr returns first listener address
- **WHEN** `Addr()` is called on a `MultiListener` created with `[":8081", ":8080"]`
- **THEN** it returns the address of the first listener (port 8081)

### Requirement: ListenMultiTCP replaces ListenTCP
The system SHALL provide a `ListenMultiTCP(ctx, addrs []string, proxyProto bool) (*MultiListener, error)` function. It SHALL create a TCP listener for each address, optionally wrapping each with PROXY protocol support. If any address fails to bind, the successfully bound listeners SHALL be closed and an error returned.

#### Scenario: All addresses bind successfully
- **WHEN** `ListenMultiTCP(ctx, [":8081", ":8080"], false)` is called and both ports are available
- **THEN** a `MultiListener` with two listeners is returned

#### Scenario: One address fails to bind
- **WHEN** `ListenMultiTCP(ctx, [":8081", ":8080"], false)` is called and port 8080 is already in use
- **THEN** the listener on 8081 is closed and an error is returned

#### Scenario: PROXY protocol applied to all listeners
- **WHEN** `ListenMultiTCP(ctx, [":8081", ":8080"], true)` is called
- **THEN** both listeners are wrapped with PROXY protocol support

### Requirement: ConnContext helper for HTTP-based traps
The system SHALL provide a `ConnContextWithDestPort` function suitable for use as `http.Server.ConnContext`. It SHALL extract the destination port from `conn.LocalAddr()` and store it in the returned context. A `DestPortFromContext(ctx) int` function SHALL retrieve it.

#### Scenario: Port stored and retrieved
- **WHEN** an HTTP connection arrives on port 8443 and `ConnContextWithDestPort` is set as `ConnContext`
- **THEN** `DestPortFromContext(r.Context())` returns 8443 in the request handler

#### Scenario: Missing context value
- **WHEN** `DestPortFromContext` is called on a context without a stored port
- **THEN** it returns 0

### Requirement: destPort from conn.LocalAddr for TCP traps
All TCP traps SHALL derive `destPort` from `conn.LocalAddr().String()` instead of from the listener address or config. This SHALL apply to all 23 raw-TCP traps (ssh, mysql, ftp, telnet, rdp, vnc, mqtt, modbus, ldap, smb, socks5, postgres, mssql, oracle, redis, memcached, pop3, imap, irc, smtp, adb, minecraft) and indirectly via ConnContext for the 3 HTTP-based traps.

#### Scenario: Single-port TCP trap reports correct destPort
- **WHEN** an SSH trap listens on `:2222` and a connection arrives
- **THEN** the session's destPort is 2222, derived from `conn.LocalAddr()`

#### Scenario: Multi-port TCP trap reports per-connection destPort
- **WHEN** an SSH trap listens on `[":2222", ":22"]` and a connection arrives on port 22
- **THEN** the session's destPort is 22, derived from `conn.LocalAddr()`
