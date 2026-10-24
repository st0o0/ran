## 1. Implementation

- [ ] 1.1 Seed generation and persistence next to the SSH host key; `RAN_FINGERPRINT` parsing and README row (contract test)
- [ ] 1.2 Banner tables for ssh, mysql, http, smtp, elasticsearch; constructors take the profile
- [ ] 1.3 `kind` meta for vnc and the other single-request traps; update the classification notes
- [ ] 1.4 README: banner notes and the one-time fingerprint change in the upgrade notes; remove the follow-up from `AGENTS.md`

## 2. Tests

- [ ] 2.1 Same seed gives the same banners, different seeds differ, fixed mode unchanged
- [ ] 2.2 Existing tests that assert banner strings read them from the profile
- [ ] 2.3 `go test -race ./...` in Docker, 386 build, lint, `openspec validate --all`
