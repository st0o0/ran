## Context

Each finding was re-verified against the 0.3.7 source.

| # | Finding | Evidence |
|---|---------|----------|
| 1 | Header IP becomes alert IP, unvalidated | `http.go:121-130` (`alertIP` overridden by `clientIPFromHeaders`), `144-155` |
| 2 | `make([]string,0,count)` and `make([]byte,length+2)` sized by client; no `recover()` anywhere | `redis.go:160-176`; no `recover(` in the repo |
| 3 | UDP handlers alert with `sess.SourceIP` | `dns.go:51`, `ntp.go:47`, `snmp.go:60`, `sip.go:78` |
| 4 | `berReadLength` accepts up to 4 length bytes then `make([]byte,length)`; `ParseForm` without `MaxBytesReader`; `ReadString('\n')` unbounded despite `bufio.NewReaderSize` | `ldap.go:179-221`, `http.go:113`, `telnet.go:100,112`, `redis.go:150,163,191`, `proxyproto.go:88` |
| 5 | `Alert()` does no IP validation | `crowdsec.go:112-136` |
| 6 | `dedupFilter.seen` and `localDecisionCache.bans` unbounded; dedup `Allow` records the slot before the non-blocking send that may drop | `dedup.go:22-33`, `decision_cache.go:50-57`, `crowdsec.go:122-135` |
| 7 | Passwords in CrowdSec meta and in logs | `crowdsec.go:316-330` (`buildEventMeta`), `Session.LogAuthAttempt` callers in every trap |
| 8 | UDP spawns a goroutine per packet; only a concurrency `Limiter` (max in-flight per IP/global) bounds it, no packet rate limit | `udp.go:68-100`, `limiter.go` |

Not found in code: any support for skipping the honeypot's own addresses. It is NOT part of this hotfix and is noted as a follow-up only.

## Goals / Non-Goals

**Goals:** remove attacker-controlled identity, remove crash and memory-exhaustion paths, keep the change small and compatible except where noted.
**Non-Goals:** see proposal.

## Decisions

### D1: Alert identity is the socket peer only
HTTP uses `sess.SourceIP`. Header values are parsed with `netip.ParseAddr` and logged as `claimed_client_ip` (omitted if invalid). A honeypot is directly exposed, so any client can send any header. Behind a trusted proxy the PROXY protocol (`proxyproto.go`) already supplies the real peer.

### D2: UDP traps never alert
Source addresses are spoofable, so an alert would let anyone ban a victim and poison CAPI. The dns, ntp, snmp and sip handlers have no `alerter` field and their constructors take no alerter, so a UDP handler cannot alert at all (a compile-time guarantee, not a convention). Logging and metrics stay. `alert.NoopAlerter` remains only for runs with CrowdSec disabled. Waiting for a handshake is impossible for these protocols.

### D3: Validation in `Alert()` (defense in depth)
`netip.ParseAddr`, reject zones, `Unmap()`, then reject any address inside an explicit denylist of `netip.Prefix` values (`nonGlobalPrefixes` in `crowdsec.go`):

- IPv4: 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10 (CGNAT), 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4.
- IPv6: ::/128, ::1/128, ::ffff:0:0/96, 64:ff9b::/96 (NAT64), 64:ff9b:1::/48 (local-use NAT64), 100::/64, 2001::/23 (IETF protocol assignments, Teredo, benchmarking), 2001:db8::/32, 2002::/16 (6to4), 3fff::/20 (documentation), 5f00::/16 (SRv6 SIDs), fc00::/7, fe80::/10, ff00::/8, ::/96 (IPv4-compatible).

Reason: documentation, benchmark, CGNAT and transition ranges are never legitimate scanner sources, and they are exactly what spoofed or misrouted traffic looks like, so banning them only helps an attacker (spoofing hardening). Private ranges are rejected because internal hosts must never be banned via CrowdSec; LAN-only deployments therefore get no CrowdSec alerts (documented). Rejections count as pipeline stage `invalid` and log at debug. Validation runs before cache and dedup so junk never enters the maps. An explicit list replaces `IsGlobalUnicast() && !IsPrivate()` because the stdlib predicates accept documentation, CGNAT, 6to4 and NAT64 addresses.

### D4: Bounded parsing
- Redis: max 128 args, max bulk 4096, line cap 4096; exceeding closes the connection with outcome `error`. Never preallocate from `count`.
- LDAP: `maxBERLen` 64 KiB, checked before `make`.
- HTTP: `http.MaxBytesReader(w, r.Body, 16<<10)` before `ParseForm`; `MaxHeaderBytes` 16 KiB.
- Line reads (telnet, redis inline, PROXY v1): shared helper `readLineLimited(r, max)` returning `bufio.ErrTooLong`.
- BER lengths: both `berReadLength` and `berReadTLV` reject length encodings over 4 bytes and convert through `fitsInt`, which rejects values that would be negative as a 32-bit `int`. The same helper guards the NTLMSSP buffer offset in `smb.go`. BER INTEGER encoding handles negative values (a client chosen message ID is echoed back), and decoding sign-extends.
- PROXY v1: the source address must parse with `netip.ParseAddr` (no zone) and the source port is parsed as `uint16`.
- PROXY header: with `RAN_PROXY_PROTOCOL` the header is REQUIRED. It is read off the accept path, one goroutine per connection, under a 3 second read deadline. A connection that sends no valid v1/v2 header (other bytes, EOF, or deadline hit) is closed and counted in `ran_proxy_protocol_dropped_total{protocol}`; it is never turned into a plain connection. At most 1024 handshakes may be pending at once (semaphore); further connections are closed immediately and counted. A handshaken connection waits at most 5 seconds for `Accept`, so a stalled consumer cannot pile up connections. `Close` closes connections still waiting for a header and never waits for them. PROXY v2 checks the version nibble (must be 2) and caps the address block at 536 bytes before allocating. Because any direct peer can forge a header, the mode must only be enabled when ran is reachable solely from a trusted proxy or tunnel.
- BER INTEGER decoding rejects a length of 0 or above 8.

### D5: Panic isolation
Helper `safely(logger, metrics, protocol, fn)` wraps per-connection handlers, the `MultiListener` accept goroutines and the UDP per-packet goroutine. On panic: increment `ran_panics_recovered_total{protocol}` (always), log at error level, let existing defers release limiter slots. The process keeps running. Logging is rate limited per protocol: the first 5 panics carry a stack trace, later ones are sampled at most once per second (no stack, with a `suppressed` count), so a crafted input cannot become a log flood. HTTP handlers are wrapped by `recoverHandler`, which counts and logs once and then aborts the connection with `http.ErrAbortHandler`; `net/http` would otherwise recover the panic itself and skip the metric. The PROXY header goroutines also run under `safely`. If `Accept` panics repeatedly, the accept goroutine sleeps with a backoff (10ms doubling to 1s, reset on success) so it cannot spin a CPU.

### D6: Bounded dedup and cache
Both maps get a max size (default 100000 entries, roughly 12 MB at ~120 B/entry; env `RAN_CROWDSEC_MAX_TRACKED`). Both are FIFO lists (`container/list`) plus a map, so insert, expiry and eviction are O(1) amortized and never scan the map under the lock: the dedup list is ordered by slot time, so an expiry sweep pops expired entries from the front; when still full the oldest entry is evicted. The decision cache evicts the oldest entry when full; its expiry sweep runs only in `cleanupLoop`. An evicted entry is simply alerted or looked up again (LAPI remains authoritative), so a full map means more LAPI traffic. The dedup slot is recorded only after a successful enqueue (or rolled back on drop), so a dropped alert can be retried. `Allow` returns a slot (generation) and `Release` only deletes a key whose stored slot matches, so a late release cannot delete a newer slot of another alert. `Close` takes a write lock and sets a closed flag that `Alert` checks under a read lock, so Alert never sends on the closed channel and Close is idempotent. An `Alert` after `Close` is counted as pipeline stage `closed`. `MarkBanned` on an existing entry keeps the later of the old and new expiry. A flood of unique sources can evict an entry that is still inside its window; a repeat alert may then pass (documented trade-off, no eviction metric).

### D7: Passwords (decision)
- CrowdSec meta: passwords are never sent. LAPI data is shared and real attacker credentials are often stolen victim credentials. Usernames stay.
- Logs: `RAN_LOG_PASSWORDS=off|mask|on`, default `off` (field omitted). `mask` logs `***` plus length. `on` restores 0.3.7 behavior. Default is safe for users who ship logs to third-party systems; researchers opt in.
- Metrics unchanged.

### D8: UDP rate limit
Token bucket per source (default 20 pkt/s, burst 40; burst smaller than the per-source rate is rejected at startup) and global (default 2000 pkt/s), checked in `readLoop` before session creation and goroutine spawn. The limiter is kept per UDP trap, so "global" means per protocol (dns, ntp, snmp and sip each have their own global bucket). Per-source state uses a map capped at 100000 sources; once the cap is reached (after an idle sweep, at most once per second) only the global bucket applies to untracked sources. Drops log at debug only, to avoid log amplification, and are counted in `ran_udp_rate_limited_total{protocol}`.

## Risks / Trade-offs

- Fewer bans from UDP and header IPs: intended, documented.
- Rejecting private IPs breaks lab setups: documented.
- Omitted passwords reduce research value by default: opt-in flag.
- A full dedup map or decision cache evicts old entries and therefore causes more LAPI traffic (documented).
- PROXY protocol headers are trusted from any direct peer, so the mode is only safe when ran is reachable solely from a trusted proxy or tunnel (documented). A source allowlist is a possible future change, flagged for `sensor-redesign`.
- A flood of unique sources can evict a dedup or decision cache entry that is still inside its window, so a repeat alert may pass; the LAPI stays authoritative. No eviction metric is added.

## Deviations from the original plan

- `ListenMultiTCP` gained `logger`, `m` and `protocol` arguments so accept-path panics can be reported; `nil` logger and metrics are tolerated.
- `proxyListener.Accept` closes a connection with a missing or malformed PROXY header and continues instead of returning the error (which ended the accept loop), and it now parses headers off the accept path under a read deadline with a bounded number of pending handshakes.
- `berReadTLV` and `berReadLength` reject length encodings over 4 bytes, not only lengths above 64 KiB.

## Migration / Backward Compatibility

- UDP: no CrowdSec alerts; scenarios `custom/ran-{dns,ntp,snmp,sip}-trap` stop appearing.
- HTTP: log field `client_ip` becomes `claimed_client_ip`; alerts use the peer IP.
- Logs: `password` field absent unless `RAN_LOG_PASSWORDS` is `on` or `mask`; CrowdSec meta has no `password` key.
- Rollback: redeploy 0.3.7; no data migration.
