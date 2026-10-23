## Why

A security review of rán 0.3.7 found issues that let a remote, unauthenticated party get arbitrary third-party IPs banned (and pushed to CrowdSec CAPI), crash the whole honeypot process, or exhaust the 128 MB container memory limit. As a public honeypot that feeds ban decisions, rán must not trust attacker-controlled input for identity. This is a targeted hotfix (release 0.3.8); the larger alerting redesign is a separate change (`sensor-redesign`, 0.4.0).

## What Changes

- **HTTP trap**: alert only on the socket peer address. `X-Real-IP` / `X-Forwarded-For` are logged as a separate `claimed_client_ip` field and never used as alert IP. (`internal/trap/http.go:121-130`, `144-155`)
- **Redis trap**: cap RESP array count and bulk length; no allocation sized by client input. (`internal/trap/redis.go:160-176`)
- **Panic isolation**: add `recover()` at accept/handler boundaries so one bad connection cannot kill all traps. No `recover()` exists in the codebase today.
- **BREAKING (behavior)**: UDP traps (dns, ntp, snmp, sip) no longer raise alerts. They log and emit metrics only, because UDP source addresses are spoofable.
- **Bounded reads**: LDAP BER length cap (`ldap.go:196-221`), HTTP `MaxBytesReader` before `ParseForm` (`http.go:113`), capped line reads for telnet (`telnet.go:100,112`), redis (`redis.go:150,163,191`) and PROXY v1 (`proxyproto.go:88`).
- **Alert() IP validation**: unmap IPv4-mapped IPv6, reject zones, and reject every address in an explicit denylist of non-global ranges (private, CGNAT, loopback, link-local, unspecified, multicast, reserved, documentation, benchmarking, NAT64, 6to4 and IPv4-compatible space).
- **Bounded memory**: cap the dedup map and local decision cache; fix lost alerts when the dedup slot is recorded before a failed non-blocking enqueue (`crowdsec.go:122-135`).
- **Passwords**: stop sending passwords as CrowdSec event meta; make password logging configurable (`RAN_LOG_PASSWORDS`, default `off`).
- **UDP flood control**: per-source and global packet rate limit before spawning a goroutine.
- **BREAKING (behavior)**: with `RAN_PROXY_PROTOCOL` on, the PROXY v1/v2 header is now required. A connection without a valid header (other bytes, EOF, or silent past the 3 second deadline) is closed and counted instead of being handled as a plain connection. Only enable the mode when ran is reachable solely from a trusted proxy or tunnel.

## Capabilities

### New Capabilities

- `trap-panic-isolation`: recover from panics at connection and packet boundaries.
- `credential-logging`: password handling in logs and CrowdSec meta.

### Modified Capabilities

- `crowdsec-alerter`: IP validation, bounded dedup/cache, enqueue-before-dedup ordering, no password meta.
- `trap-http`: peer-only alert IP, body size limit, header IP logged separately.
- `udp-trap-base`: no alerting, packet rate limiting.
- `input-size-limits`: LDAP, telnet, redis, PROXY line/length caps.
- `trap-redis`: bounded RESP parsing.

## Impact

- Code: `internal/trap/{http,redis,ldap,telnet,udp,proxyproto,trap}.go`, `internal/alert/{crowdsec,dedup,decision_cache}.go`, `internal/config`.
- New env vars: `RAN_LOG_PASSWORDS`, `RAN_UDP_RATE_*`, `RAN_CROWDSEC_MAX_TRACKED` (details in design.md).
- Specs `trap-dns`, `trap-ntp`, `trap-snmp`, `trap-sip` say "alert CrowdSec" and must be updated when specs are synced.
- Users relying on UDP-triggered bans or header-derived IPs will see fewer bans (intended).

## Non-goals

Alerts without decisions, trap classes, cooldowns, scan detection and trap removal (all `sensor-redesign`, 0.4.0). No new protocols. No IP allow-listing (dynamic IPs make it unsuitable).
