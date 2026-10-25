## 1. Implementation

- [x] 1.1 Seed generation and persistence next to the SSH host key; `RAN_FINGERPRINT` parsing and README row (contract test)
- [x] 1.2 Banner tables for ssh, mysql, http, smtp, elasticsearch; constructors take the profile
- [x] 1.3 `kind` meta for vnc and the other single-request traps; update the classification notes
- [x] 1.4 README: banner notes and the one-time fingerprint change in the upgrade notes; remove the follow-up from `AGENTS.md`

## 2. Tests

- [x] 2.1 Same seed gives the same banners, different seeds differ, fixed mode unchanged
- [x] 2.2 Existing tests that assert banner strings read them from the profile
- [x] 2.3 `go test -race ./...` in Docker, 386 build, lint, `openspec validate --all`
