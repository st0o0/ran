## Why

With `RAN_PROXY_PROTOCOL=on` any peer that can reach the port may send a forged PROXY header and choose the source address rán reports, so a public IP can be reported and then banned. The README advises firewalling the listener, but rán itself offers no check. This is listed in `AGENTS.md` as a known follow-up.

## What Changes

- New `RAN_PROXY_TRUSTED`: comma-separated IPs and CIDRs of peers that may send PROXY headers. Validated at startup; with `RAN_PROXY_PROTOCOL=on` it is required unless `RAN_PROXY_TRUSTED=any` is set explicitly (migration escape hatch, logged as a warning).
- A connection from an untrusted peer is closed before the header is read and counted in `ran_proxy_protocol_dropped_total{protocol}` with the existing label set (no new cardinality).
- The check uses the socket peer address, never header contents.

## Capabilities

### Modified Capabilities

- `proxy-protocol` behavior in `multi-port-listener`/`config`.

## Impact

- `internal/trap/proxyproto.go`, `internal/config/config.go`, README (threat model and config rows), tests. **BREAKING**: an existing setup with `RAN_PROXY_PROTOCOL=on` and no `RAN_PROXY_TRUSTED` fails `check-config` until it sets the variable (mark the commit with `!`).

## Non-goals

- No TLV or authentication of the proxy.
- No dynamic trust list.
- No change for deployments with the protocol off.
