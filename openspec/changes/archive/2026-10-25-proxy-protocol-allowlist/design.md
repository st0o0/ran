## Where the check sits

`proxyListener.acceptLoop` checks `conn.RemoteAddr()` right after `Accept` returns, before the handshake semaphore is taken, before any goroutine is spawned and before a single byte is read. An untrusted peer is closed through the existing `drop` path (`ran_proxy_protocol_dropped_total{protocol}`, debug log with a reason only, no addresses). Because it runs ahead of the pending-header cap, untrusted floods never consume one of the 1024 handshake slots, so they cannot starve the trusted proxy. The check covers every TCP trap, because they all reach `ListenMultiTCP` (raw TCP skeleton, `http`, `httpproxy`, `elasticsearch`); UDP never builds a `proxyListener`.

`ListenMultiTCP` now takes a `*config.ProxyTrust` instead of a bool; nil means the protocol is off. `Config.ProxyTrust()` returns nil when `RAN_PROXY_PROTOCOL` is off. A nil trust handed to `newProxyListener` trusts nobody (fail closed).

## Matching

Entries are parsed with `ParseIgnoreList` (same normalization, 1024 limit, wide-range detection), so there is one parser to fuzz. Matching is a linear scan over at most 1024 prefixes per accepted connection, once, on the socket peer (`*net.TCPAddr` addr, IPv4-mapped unmapped). That costs microseconds and is cheaper than the accept itself; a trie is not worth it. An address that cannot be parsed is untrusted.

## `any`

`RAN_PROXY_TRUSTED=any` (exact, after trimming; `ANY` and mixed lists such as `any,10.0.0.1` are rejected) sets `ProxyTrustAny` and trusts every peer. It logs a WARN at startup and a warning in `check-config`. It exists only as a migration aid.

## Set but protocol off

Decision: accept and ignore, with a warning at startup and in `check-config`. Rejecting would make it impossible to switch the protocol off temporarily without editing the trust list. The value is still validated, so a typo is not hidden.

## Wide ranges

Prefixes shorter than /8 warn (startup log and `check-config`), like the ignore list; the threshold is /8 for both IPv4 and IPv6, so an IPv6 /16 or an IPv4 /9 does not warn. They are accepted.

## Tests

Test configs that use PROXY protocol from loopback clients set `ProxyTrusted` to `127.0.0.0/8,::1/128`. The end-to-end test trusts only `127.0.0.2/32` and dials from that source address to show the trusted and untrusted outcomes against one trap.
