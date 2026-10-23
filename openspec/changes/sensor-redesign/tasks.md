## 1. Implementation

- [ ] 1.1 Add payload byte counter to `Session` and expose counters to the alerter
- [ ] 1.2 Implement classifier (probe/attack) and capped scan tracker (TCP only, 3 protocols, 10 min)
- [ ] 1.3 Remove embedded decision, set `remediation: true`, add class/protocol/dest_port/counter meta in `crowdsec.go`
- [ ] 1.4 Replace decision cache and dedup with per-IP+class cooldown (capped map, class-escalation bypass)
- [ ] 1.5 Add `RAN_BAN_ON` and `RAN_ALERT_COOLDOWN` to config; drop `RAN_CROWDSEC_BAN_DURATION`, cache and dedup vars with one-time warning
- [ ] 1.6 Update pipeline metric stages (`filtered`, `cooldown`); keep other `ran_*` names and labels
- [ ] 1.7 Implement aggregated probe logging per IP and window
- [ ] 1.8 Delete `decision_cache.go` and `dedup.go` and their tests; wire `cmd/ran`

## 2. Tests

- [ ] 2.1 Classifier and scan tracker unit tests (UDP ignored, window expiry, cap eviction)
- [ ] 2.2 Alerter tests: no decisions, remediation true, meta keys, filtered, cooldown, escalation bypass
- [ ] 2.3 Config tests for new and removed variables
- [ ] 2.4 Metrics tests for new stages and unchanged names
- [ ] 2.5 Log aggregation tests and integration test against a fake LAPI

## 3. Docs

- [ ] 3.1 Rewrite README CrowdSec section: sensor model, config table, pipeline diagram
- [ ] 3.2 Add profiles.yaml example keyed by class and CrowdSec behavior notes (CAPI, simulated, allowlists, flush settings)
- [ ] 3.3 Add 0.3.x to 0.4.0 migration notes
- [ ] 3.4 Sync delta specs to main specs; resolve `dynamic-ban-escalation` before archive

## 4. Release

- [ ] 4.1 Confirm `security-hotfix` (0.3.8) is released
- [ ] 4.2 Update Grafana dashboards using `cached`/`deduplicated` stages
- [ ] 4.3 Cut 0.4.0 via release-please with breaking-change notes
