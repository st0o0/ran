## 1. Implementation

- [ ] 1.1 Config: parse and validate `RAN_PROXY_TRUSTED` (IPs, CIDRs, `any`), cross-check with `RAN_PROXY_PROTOCOL`
- [ ] 1.2 Listener: check the socket peer before reading a header; drop and count untrusted peers
- [ ] 1.3 Startup warning for `any`; README threat model, config table and migration note; remove the follow-up from `AGENTS.md`

## 2. Tests

- [ ] 2.1 Parsing table (v4, v6, CIDR, mapped, `any`, invalid)
- [ ] 2.2 Untrusted peer with a valid header is dropped; trusted peer works; `LOCAL`/`UNKNOWN` headers keep the proxy address only for trusted peers
- [ ] 2.3 Existing `proxy_required_test.go` updated, no goroutine leak
- [ ] 2.4 `go test -race ./...` in Docker, 386 build, lint, `openspec validate --all`
