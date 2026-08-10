## Context

ran is a single Go binary honeypot with 3 traps (SSH, HTTP, MySQL). Each trap implements the `Trap` interface (`Start`/`Stop`), uses a shared `Session` for structured logging and metrics, a `Limiter` for rate limiting, and an `Alerter` for CrowdSec integration. Config is env-var driven. All traps are TCP-based. We're adding 24 new traps (20 TCP, 4 UDP) to achieve comprehensive protocol coverage.

## Goals / Non-Goals

**Goals:**
- Add 24 new protocol traps covering the most-scanned services on the internet
- Introduce UDP listener pattern for DNS, SNMP, SIP, NTP
- Simplify configuration for many traps via `RAN_TRAPS` list
- Keep all traps pure Go — no CGO, no external binary dependencies
- Maintain the existing architecture: Trap interface, Session, Limiter, Alerter

**Non-Goals:**
- Full protocol emulation (interactive shells, file systems, query execution) — traps capture connection metadata and credentials, then reject
- TLS termination on individual traps (except RDP which needs it minimally for the handshake)
- Tarpit/slowloris modes (future enhancement)
- Web UI or management dashboard
- Clustering or distributed deployment

## Decisions

### 1. TCP trap base pattern: keep current, no abstraction

Each TCP trap directly implements `Trap` with its own `net.Listen` + accept loop. The existing SSH/HTTP/MySQL traps already do this and the code is straightforward (~20 lines of boilerplate per trap). Extracting a `TCPTrapBase` struct would save ~15 lines per trap but adds indirection and makes each trap harder to understand in isolation.

**Alternative considered:** Generic `TCPTrapBase` with `HandleConn` callback — rejected because different traps need different listener configurations (HTTP uses `http.Server.Serve`, SSH needs the signer setup, etc.).

### 2. UDP trap pattern: shared `UDPTrap` helper

UDP traps share a `net.ListenPacket` + `ReadFrom` loop that's meaningfully different from TCP. A `UDPConn` helper struct provides: listen, read packet, write response, shutdown. Each UDP trap implements a `HandlePacket(addr net.Addr, data []byte)` method. This is worth abstracting because all 4 UDP traps have the same loop structure and the boilerplate is more error-prone (buffer sizing, deadline handling on packet connections).

### 3. Config: `RAN_TRAPS` list + per-trap addr overrides

Current style (`RAN_SSH=on`, `RAN_HTTP=on`, ...) doesn't scale to 27 traps. New approach:

```
RAN_TRAPS=ssh,http,mysql,ftp,telnet,redis,smtp    # comma-separated list
RAN_FTP_ADDR=:2121                                  # optional per-trap override
```

- `RAN_TRAPS` is the primary way to enable traps. Each trap has a default port.
- Legacy `RAN_SSH=on` / `RAN_HTTP=on` / `RAN_MYSQL=on` still work for backwards compat.
- If neither `RAN_TRAPS` nor any `RAN_<PROTO>=on` is set, error out (same as current).
- Default ports are defined in a `defaultPorts` map, overridable via `RAN_<PROTO>_ADDR`.

### 4. Session extensions: LogCommand and LogPayload

Current `Session` has `LogConnect`, `LogAuthAttempt`, `LogDisconnect`. Some traps don't capture credentials but capture commands (Redis, Memcached, Elasticsearch) or raw payloads (DNS queries, SNMP community strings, Modbus function codes). Add:

- `LogCommand(logger, command string, args ...slog.Attr)` — for command-oriented protocols (Redis, Memcached, IRC)
- `LogPayload(logger, payloadType string, attrs ...slog.Attr)` — for binary/query protocols (DNS, SNMP, Modbus, NTP, SIP)

These use the same structured logging pattern with `action` field set to `"command"` or `"payload"`.

### 5. Trap implementation depth — minimal viable emulation

Each trap emulates just enough protocol to:
1. Complete the initial handshake/banner exchange
2. Capture credentials (if auth-based) or first command/query (if command-based)
3. Return a plausible error and close

No interactive sessions, no filesystem emulation, no query execution. This keeps each trap to 50-200 LOC and minimizes attack surface on the honeypot itself.

Specific protocol depths:

| Protocol | Emulation Level |
|----------|----------------|
| FTP | Banner → USER/PASS → "Login incorrect" |
| Telnet | Banner → login/password prompts → reject |
| SMTP | 220 banner → EHLO → AUTH LOGIN → reject |
| POP3 | +OK banner → USER/PASS → -ERR |
| IMAP | * OK banner → LOGIN command → NO |
| LDAP | Accept bind → return invalidCredentials |
| SMB | SMB negotiate → session setup → ACCESS_DENIED |
| SOCKS5 | Version handshake → auth if offered → reject |
| MSSQL | TDS prelogin → login → error token |
| Oracle | TNS connect → accept → auth → refuse |
| PostgreSQL | Startup → AuthenticationCleartextPassword → ErrorResponse |
| Redis | Accept RESP commands → log → -ERR |
| RDP | X.224 CR → CC → reject (no TLS/CredSSP) |
| VNC | RFB version → security type VNC auth → reject |
| Memcached | Accept text commands → log → ERROR |
| Elasticsearch | HTTP GET/PUT/POST → fake cluster info JSON → log |
| IRC | NICK/USER → welcome → capture |
| MQTT | CONNECT → CONNACK with auth failure |
| Modbus | Read function code → log → exception response |
| HTTP Proxy | CONNECT/GET → log target → 407 Proxy Auth Required |
| DNS (UDP) | Parse query → log → REFUSED |
| SNMP (UDP) | Parse GetRequest → log community string → noSuchName |
| SIP (UDP) | Parse REGISTER/INVITE → log → 401 Unauthorized |
| NTP (UDP) | Parse mode → log → KoD response |

### 6. File organization: one file per trap

Follow existing pattern: `internal/trap/<protocol>.go` + `internal/trap/<protocol>_test.go`. No sub-packages. The `trap` package stays flat.

### 7. Trap registry for run.go

Instead of a growing `if cfg.SSH { ... } if cfg.HTTP { ... }` chain, introduce a registry map:

```go
var registry = map[string]func(*config.Config, *slog.Logger, *metrics.Metrics, *Limiter, alert.Alerter) (Trap, error){
    "ssh":   func(...) (Trap, error) { return NewSSH(...) },
    "http":  func(...) (Trap, error) { return NewHTTP(...), nil },
    ...
}
```

`run.go` iterates `cfg.EnabledTraps()` and looks up the factory. This is the cleanest way to handle 27 traps without a massive if-chain.

## Risks / Trade-offs

**[Binary size increase]** → 24 new trap files add ~2500 LOC. Negligible impact on binary size (~100KB). No new dependencies expected.

**[Port conflicts in deployment]** → Running 27 traps means 27 ports. Users need to be intentional about which traps to enable. Default config requires explicit `RAN_TRAPS` list. Documentation must clearly list default ports.

**[Protocol correctness]** → Minimal emulation means some scanners may detect the honeypot. Acceptable trade-off: we optimize for breadth of detection over depth of deception.

**[UDP amplification risk]** → DNS/NTP/SNMP traps could theoretically be used for amplification if the honeypot itself is misconfigured. Mitigation: responses are minimal/empty, and the Limiter applies to UDP source IPs too. Document that UDP traps should be behind a firewall that prevents spoofed source IPs.

**[SMB complexity]** → SMB is the most complex binary protocol. Keeping it to negotiate + session setup avoids the deep protocol tree, but the initial implementation may need iteration to handle Windows vs Linux clients.
