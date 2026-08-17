## Why

RAn has 27 protocol traps but each can only bind a single port. In practice, scanners hit the same protocol on multiple well-known ports (e.g. HTTP probes on :8080, :8443, :3128; MySQL scanners on :3306 and :3307). Today this requires either ignoring those ports or running duplicate trap instances — neither scales. Additionally, two commonly scanned ports (ADB :5555 and Minecraft :25565) have no matching trap at all. Multi-port support plus two lightweight new traps would let a single RAn instance cover the top 30+ scanned ports without new protocol code.

## What Changes

- **Multi-port listen addresses**: `RAN_<PROTO>_ADDR` accepts comma-separated addresses (e.g. `RAN_HTTP_ADDR=:8081,:8080,:8443,:3128`). A single trap instance opens multiple listeners and accepts connections from all of them. Backward-compatible — a single address still works as before.
- **MultiListener infrastructure**: New `MultiListener` type that wraps N `net.Listener` behind one `Accept()` call. Equivalent `MultiPacketConn` for UDP traps.
- **destPort from connection**: All traps switch from deriving `destPort` from the listener/config to deriving it from `conn.LocalAddr()` (TCP) or packet local address (UDP). HTTP-based traps use `ConnContext` to propagate the port into `r.Context()`. This is more correct even for single-port and is required for multi-port.
- **ADB trap** (new): Accepts TCP connections on :5555 (default), reads the ADB `CNXN` message, responds with an `AUTH` token request, logs connection metadata, alerts, and closes.
- **Minecraft trap** (new): Accepts TCP connections on :25565 (default), reads the Minecraft handshake packet (protocol version, server address, next state), responds with a status response (server info JSON), logs, alerts, and closes.

## Capabilities

### New Capabilities
- `multi-port-listener`: Infrastructure for binding a single trap to multiple listen addresses, including MultiListener (TCP) and MultiPacketConn (UDP), plus ConnContext-based port propagation for HTTP-based traps.
- `trap-adb`: ADB (Android Debug Bridge) honeypot trap on TCP port 5555.
- `trap-minecraft`: Minecraft server honeypot trap on TCP port 25565.

### Modified Capabilities
- `config`: `TrapAddr()` returns comma-separated addresses; new `TrapAddrs()` method returns `[]string`. Default ports list extended with ADB and Minecraft entries.
- `trap-http`: destPort derived from `ConnContext`/`r.Context()` instead of config, to support multi-port.
- `trap-httpproxy`: destPort derived from `ConnContext`/`r.Context()` instead of config, to support multi-port.
- `trap-elasticsearch`: destPort derived from `ConnContext`/`r.Context()` instead of config, to support multi-port.
- `udp-trap-base`: destPort derived from packet local address instead of stored field, to support multi-port UDP.

## Impact

- **internal/config**: `TrapAddr()` signature unchanged (returns first addr for backward compat), new `TrapAddrs()` method, `DefaultPorts` extended with `adb` and `minecraft` entries.
- **internal/trap/trap.go**: New `MultiListener` type (~50 LOC), new `ListenMultiTCP()` function, new `ConnContext` helper and context key for HTTP-based traps.
- **internal/trap/udp.go**: New `ListenMultiUDP()` or equivalent for multi-port UDP, destPort from packet address.
- **All 27 existing trap files**: Mechanical change — `ListenTCP` → `ListenMultiTCP`, destPort from `conn.LocalAddr()` or `r.Context().Value()`. No protocol logic changes.
- **internal/trap/adb.go** (new): ~100 LOC.
- **internal/trap/minecraft.go** (new): ~100 LOC.
- **internal/trap/registry.go**: Two new entries (`adb`, `minecraft`).
- **Startup logging**: Changes from single `"addr"` field to `"addrs"` list per trap.
- **No breaking changes**: Single-address config continues to work identically.
