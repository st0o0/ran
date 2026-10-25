## 1. Config

- [x] 1.1 Parse `RAN_PROXY_PROTOCOL` (`on`, `off`, trap list), `ProxyProtocolFor(name)`, validation (unknown, UDP), docs rows for the contract test
- [x] 1.2 `RAN_PROXY_TRUSTED` required when any trap uses PROXY; `ProxyTrustedUnused` follows the new logic

## 2. Listeners

- [x] 2.1 TCP skeleton and HTTP traps decide per trap
- [x] 2.2 Startup log and `ran check-config` print the effective set

## 3. Tests and docs

- [x] 3.1 Mixed deployment test: one proxied trap and one direct trap on port 0, both behave correctly
- [x] 3.2 Existing `on`/`off` tests unchanged and green
- [x] 3.3 Docs: reverse proxy section (Caddy `proxy_protocol v2`, shared namespace, loopback trust)
- [x] 3.4 `go test -race ./...` in Docker, `GOARCH=386` vet, lint, `openspec validate --all`
