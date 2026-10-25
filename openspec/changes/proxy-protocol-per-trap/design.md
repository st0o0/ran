## Parsing

`RAN_PROXY_PROTOCOL` values: `on`/`true`/`1` (all TCP traps), `off`/`false`/`0` or empty (none), otherwise a list of trap names that must be enabled TCP traps. A list that names a trap not in `RAN_TRAPS` is accepted with a startup warning (the trap may be added later by a different environment), but a name that is not a valid trap, or a UDP trap, is an error. The config exposes a `ProxyProtocolFor(name) bool` so the listener code does not interpret the raw value.

## Listener

The shared TCP skeleton already wraps the listener in `proxyListener` when the setting is on. The decision moves from `cfg.ProxyProtocol` to `cfg.ProxyProtocolFor(proto)`. The HTTP traps (`http.Server`) use the same wrapper. Nothing else changes: trust check on the socket peer, handshake cap and timeout, drop reason metric.

## Trust

`RAN_PROXY_TRUSTED` is required if any trap uses PROXY. The list is shared; it is the operator's job to keep it narrow. The shared-namespace case (proxy and ran in one network namespace) needs `::1` and `127.0.0.1`.

## Risks

- A typo in the trap list silently disables PROXY for a trap that is directly reachable. Mitigation: the startup log and `check-config` print the effective set, and an unknown name is an error.
- A trap that is proxied and also reachable directly on another port would drop the direct connections. Documented: one trap name means one setting; use a second port only through the proxy.
