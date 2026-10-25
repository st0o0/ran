## Why

`RAN_PROXY_PROTOCOL` is global. With it on, every listener requires a PROXY header from a trusted peer and drops everyone else (`untrusted_peer`). A host that mixes traps reachable directly from the internet (VNC, SSH, RDP, ...) with one trap fronted by a reverse proxy (for example the HTTP trap behind Caddy) cannot use it: enabling it would drop every direct connection.

Measured on such a host (7 days): the proxied HTTP trap saw 1083 sessions, all from the loopback address of the proxy. The real client IPs of those visitors (about 75 distinct sources) were never classified or reported, so they could not be banned or shared. The alert pipeline rejects loopback, so nothing wrong was sent, but the signal was lost.

## What Changes

- `RAN_PROXY_PROTOCOL` accepts `on`, `off` (default), or a comma-separated list of trap names (for example `http,https`). `on` keeps today's meaning (all TCP traps). With a list, only the named traps require and parse a PROXY header; all other traps behave as if it were off.
- `RAN_PROXY_TRUSTED` stays mandatory whenever any trap uses PROXY (a list, `on`) and applies to the traps that use it. The socket peer is checked before the header is read, as today.
- Unknown or UDP trap names in the list fail the startup validation with a clear message (UDP traps cannot use PROXY protocol).
- Startup log names the traps that expect a PROXY header and the trusted peers.
- Docs: a "behind a reverse proxy" section with the Caddy recipe (`proxy_protocol v2` in the upstream transport of the honeypot route), the shared-network-namespace case (trust the loopback addresses), and the note that headers like `X-Forwarded-For` are still only logged.
- `ran check-config` reports the effective per-trap PROXY setting.

## Capabilities

### Modified Capabilities

- `proxy-protocol` (per-trap selection).

## Impact

- `internal/config` (parsing, validation, README/docs rows for the contract test), `internal/trap` (listener wrapping decided per trap), `cmd/ran` startup log and `check-config`, docs, tests.
- Backward compatible: `on` and `off` behave as before. A list is new syntax.

## Non-goals

- No auto-detection of PROXY headers on untrusted peers, no per-peer exceptions inside a trap.
- No trust in headers other than the PROXY header.
