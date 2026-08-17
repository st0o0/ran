## Context

RAn is a multi-protocol honeypot with 27 traps, each binding a single listen address. The configuration stores one address string per trap in `Config.Addrs[name]`. TCP traps call `ListenTCP()` which returns a single `net.Listener`; UDP traps call `net.ListenPacket()` for a single `net.PacketConn`. The destination port logged per session is derived from the listener address (TCP) or stored at construction time (UDP), not from the actual connection.

Three trap types use `http.Server.Serve(ln)` instead of a raw accept loop: `http`, `httpproxy`, and `elasticsearch`. These derive `destPort` from `cfg.TrapAddr()` because `http.Handler`/`http.HandlerFunc` don't expose the underlying `net.Conn`.

## Goals / Non-Goals

**Goals:**
- Allow any trap to bind multiple comma-separated addresses via `RAN_<PROTO>_ADDR`
- Derive destPort from the actual connection/packet, not from config — correct for both single and multi-port
- Add ADB and Minecraft traps
- Zero protocol-logic changes in existing traps — the migration is purely mechanical

**Non-Goals:**
- Per-port protocol variation (e.g. different HTTP behavior on :8080 vs :8443)
- TLS termination on alternate ports
- Dynamic port addition at runtime (restart required)
- A generic "raw TCP" catch-all trap

## Decisions

### 1. MultiListener behind a single Accept()

**Decision:** Implement a `MultiListener` type that wraps `[]net.Listener` and exposes a single `Accept()` via a shared channel. Each internal listener runs its own accept goroutine pushing to the channel.

**Alternatives considered:**
- *Each trap manages its own listener slice:* Would require changing the accept loop in all 23 TCP traps. High blast radius.
- *Return []Trap from factory (one per address):* Would multiply trap instances, break per-protocol metrics grouping, and complicate shutdown.

**Rationale:** MultiListener keeps every trap's `Start()` method unchanged — they see one listener. The destination port is always available via `conn.LocalAddr()`.

```
type MultiListener struct {
    listeners []net.Listener
    connCh    chan net.Conn
    errCh     chan error
    done      chan struct{}
    closeOnce sync.Once
}

func (ml *MultiListener) Accept() (net.Conn, error)  // reads from connCh
func (ml *MultiListener) Close() error                // closes all listeners
func (ml *MultiListener) Addr() net.Addr              // returns first listener's addr
```

`Addr()` returns the first listener's address for backward-compatible log messages. The actual port comes from `conn.LocalAddr()`.

### 2. destPort from conn.LocalAddr() instead of listener/config

**Decision:** All TCP traps switch from `ParseAddr(t.listener.Addr().String())` or `ParseAddr(t.cfg.TrapAddr(...))` to `ParseAddr(conn.LocalAddr().String())` for destPort.

**Rationale:** This is more correct even for single-port (if the OS picks a port via `:0`). It's the only approach that works for multi-port without passing extra state.

### 3. ConnContext for HTTP-based traps

**Decision:** HTTP-based traps (`http`, `httpproxy`, `elasticsearch`) use `http.Server.ConnContext` to stash `conn.LocalAddr()` port into the request context. A package-level context key and helper function provide access.

```go
var destPortCtxKey = contextKey("destPort")

func withDestPort(ctx context.Context, conn net.Conn) context.Context {
    _, port := ParseAddr(conn.LocalAddr().String())
    return context.WithValue(ctx, destPortCtxKey, port)
}

func DestPortFromContext(ctx context.Context) int {
    if v, ok := ctx.Value(destPortCtxKey).(int); ok {
        return v
    }
    return 0
}
```

**Alternatives considered:**
- *Wrap http.ResponseWriter to carry port:* Invasive, breaks type assertions.
- *Use r.Host header:* Unreliable — client-controlled, may be spoofed or absent.
- *Store per-conn in sync.Map:* Already done for HTTP sessions; adding another map is redundant when ConnContext exists.

### 4. Multi-port UDP via multiple goroutines

**Decision:** The `UDPTrap` changes from a single `net.PacketConn` to `[]net.PacketConn`. Each conn runs its own read loop. The destPort is derived from the packet conn's local address per-packet rather than stored at construction.

**Rationale:** Unlike TCP, there's no Accept() to unify. Each UDP socket is independent. Multiple read goroutines feeding into the same handler is natural — the handler is already stateless per-packet.

### 5. Config: TrapAddrs() returns []string, TrapAddr() returns first

**Decision:** Add `TrapAddrs(name) []string` that splits the stored address string on commas. Keep `TrapAddr(name) string` returning the raw (possibly comma-separated) string for backward compat in log messages. The addr string is stored as-is in `Config.Addrs`.

**Rationale:** Minimal config change. The splitting happens at use-site (`ListenMultiTCP`/`NewUDP`), not in config loading. Validation (no empty segments, valid addr format) happens in `ListenMultiTCP`.

### 6. ListenMultiTCP as the single entry point

**Decision:** Replace `ListenTCP` with `ListenMultiTCP(ctx, addrs []string, proxyProto bool) (*MultiListener, error)`. If `addrs` has one element, the MultiListener still works (just wraps one listener). Remove `ListenTCP` entirely — no reason to keep both.

**Rationale:** One code path, always correct. No conditional logic in traps.

### 7. ADB trap: minimal CNXN/AUTH exchange

**Decision:** The ADB trap reads the 24-byte ADB message header. If the command is `CNXN` (0x4e584e43), it extracts the system identity string from the payload. It responds with an `AUTH` token message (type 1) containing random bytes, prompting the client to authenticate. The connection is then closed after logging.

**Rationale:** Real ADB clients send CNXN immediately on connect. The AUTH response makes the exchange look realistic and extracts the client's system identity (e.g. `host::features=...`) which is useful for fingerprinting.

### 8. Minecraft trap: handshake + status response

**Decision:** The Minecraft trap reads the initial handshake packet (varint length, packet ID 0x00, protocol version, server address, server port, next state). If next state is Status (1), it responds with a status response JSON containing fake server info. If next state is Login (2), it reads the Login Start packet to extract the player name, then sends a Disconnect packet with a "maintenance" message.

**Rationale:** Most Minecraft scanners use the status ping flow. Extracting the player name from Login attempts provides additional intelligence. The varint encoding is simple (~10 lines).

## Risks / Trade-offs

**[Port conflicts between traps]** → If a user configures `RAN_HTTP_ADDR=:8080` while also enabling `httpproxy` (default :8080), both will try to bind the same port. → Mitigation: The existing startup error collection already handles bind failures — one trap fails, the other succeeds, the failure is logged. No new code needed. Could add a pre-flight duplicate check in config validation as a future improvement.

**[Channel backpressure in MultiListener]** → If Accept goroutines outpace the trap's accept loop, the channel fills up. → Mitigation: Use a buffered channel (capacity 64). Under normal load this is more than enough. If the channel is full, the accept goroutine blocks — this is correct backpressure behavior identical to a single listener.

**[27 files need mechanical edits]** → Risk of introducing bugs through repetition. → Mitigation: Each edit is the same 1-2 line pattern. The change is testable: existing tests continue to pass (single-port still works). Multi-port behavior is tested via new integration tests.

## Open Questions

None — the design is straightforward and all decisions follow from the constraint of minimal trap-code changes.
