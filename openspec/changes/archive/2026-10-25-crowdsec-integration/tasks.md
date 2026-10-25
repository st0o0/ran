## 1. Spike: container facts (first, before writing the test)

- [x] 1.1 Run `crowdsecurity/crowdsec` as LAPI only locally; record the environment variables for machine and bouncer registration, the profile mount path, the allowlist command (`cscli allowlists`) and the readiness probe. Write the verified facts into `design.md`
- [x] 1.2 Pick the image tag and digest; add a renovate rule if the preset does not already track it

## 2. Profile

- [x] 2.1 `internal/crowdsecprofile` with embedded `profiles.yaml` (`ran_scan`, `ran_attack`, `ran_noban`) and a unit test that parses it as YAML and checks the filters and `on_success`
- [x] 2.2 `ran crowdsec-profile` subcommand (no configuration needed), test, usage text
- [x] 2.3 docgen emits `docs/crowdsec-profile.generated.md`; `docs/crowdsec.md` includes it; drift test

## 3. Integration test

- [x] 3.1 `internal/alert/crowdsec_it_test.go` (build tag `crowdsec`, skip without `RAN_CROWDSEC_IT`): start the container, register, push via `CrowdSecAlerter`, assert scan/attack ban, escalation 1h then 3h (and 9h, 27h, 81h), the cap at 168h from the sixth alert on with the ban renewed rather than shortened, probe no decision, allowlist no decision
- [x] 3.2 Workflow `.github/workflows/crowdsec-it.yml` (pull request on relevant paths, weekly schedule, `workflow_dispatch`, timeout)
- [x] 3.3 Local run documented in `AGENTS.md`

## 4. Docs and verification

- [x] 4.1 `docs/crowdsec.md` and README: tested version, `ran_noban`, default-profile interplay, subcommand, example without a hand-copied profile
- [x] 4.3 Docs "what the ban protects": a reverse proxy bouncer only covers HTTP, trap ports stay open unless a firewall bouncer or `RAN_SHUN` (see `quiet-repeat-offenders`) enforces the ban there; persistent sources renew their ban; escalation pins at the cap; measured overlap of trap sources and proxied sites was small, so the main value is detection and community sharing
- [x] 4.4 Docs "reading the logs": UDP sources are spoofable and must be excluded from attacker counts (filter `transport=tcp`); a short query cookbook for the log stack in use is optional
- [x] 4.5 Decide and document the community sharing choice per class (`scan` and `attack` shared, `probe` never alerts) after checking in code what is sent
- [x] 4.2 `go test ./...`, `GOARCH=386` build and vet, lint, race detector in Docker, `openspec validate --all`, docs build
