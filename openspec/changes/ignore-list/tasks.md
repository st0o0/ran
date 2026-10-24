## 1. Implementation

- [ ] 1.1 Config: parse `RAN_IGNORE_IPS` into `[]netip.Prefix`, validation errors, `check-config` output, README row (contract test)
- [ ] 1.2 Sensor: match after unmapping the address, before `classify`; skip scan tracker and probe log
- [ ] 1.3 Session log marker `ignored` and startup log line
- [ ] 1.4 Metric `ran_ignored_sessions_total{protocol}` and pipeline stage `ignored`; README metrics list

## 2. Tests

- [ ] 2.1 Parsing table: v4, v6, CIDR, mapped, duplicates, invalid, empty entries
- [ ] 2.2 Sensor: ignored attack, probe and scan produce no events and no tracker entries
- [ ] 2.3 Limiter still counts ignored sources
- [ ] 2.4 `go test -race ./...` in Docker, 386 build, lint, `openspec validate --all`
