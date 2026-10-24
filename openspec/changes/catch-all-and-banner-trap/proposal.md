## Why

Scanners hit many ports for which rán has no named trap. Those connections are refused by the host and never counted, so the breadth-based scan detection misses them. T-Pot (Honeytrap, Glutton) and OpenCanary (`tcpbanner`) cover this with a generic listener.

## What Changes

- New trap `catchall` (no default port; configured by `RAN_CATCHALL_ADDR`, a list of ports): accepts the connection, waits up to a short window for the first bytes, logs up to 256 bytes (hex and printable) and sniffs the protocol (TLS ClientHello, HTTP request line, SMB, SSH banner, RDP, empty). The session counts the first bytes as payload only when something was sent; a silent connect stays a `probe`.
- New trap `banner` (`RAN_BANNER_<n>` style or a small list `RAN_BANNER_SERVICES=port=name:banner`): sends a configured banner on connect and an optional reply string, then logs what the client sends (bounded). Up to 10 services.
- Both use the shared TCP skeleton, appear in `/healthz` and in the registry, and use the protocol label `catchall` or `banner` for metrics (bounded label set).
- Scan detection counts them as protocols, so a source spraying unusual ports becomes a `scan`.

## Capabilities

### New Capabilities

- `trap-catchall`, `trap-banner`.

### Modified Capabilities

- `config-traps-list`: both traps added.

## Impact

- New `catchall.go`, `banner.go`, config parsing and validation for the banner list, README, contract tests. The host must route the ports to the container (documented, no iptables inside).

## Non-goals

- No iptables/nftables REDIRECT inside the container and no raw sockets.
- No per-service protocol emulation (that is what named traps are for).
- No more than 10 banner services and no dynamic reload.
