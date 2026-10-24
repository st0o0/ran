## 1. Implementation

- [x] 1.1 Config: parse `RAN_IGNORE_IPS` into `[]netip.Prefix`, validation errors, `check-config` output, README row (contract test)
- [x] 1.2 Sensor: match after unmapping the address, before `classify`; skip scan tracker and probe log
- [x] 1.3 Session log marker `ignored` and startup log line
- [x] 1.4 Metric `ran_ignored_sessions_total{protocol}` (no pipeline stage, see design.md); README metrics list

## 2. Tests

- [x] 2.1 Parsing table: v4, v6, CIDR, mapped, duplicates, invalid, empty entries
- [x] 2.2 Sensor: ignored attack, probe and scan produce no events and no tracker entries
- [x] 2.3 Limiter still counts ignored sources
- [x] 2.4 `go test -race ./...` in Docker, 386 build, lint, `openspec validate --all`
