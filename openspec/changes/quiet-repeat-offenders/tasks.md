## 1. Config

- [x] 1.1 `RAN_SHUN` (default off), `RAN_REPEAT_AFTER` (default 5), `RAN_REPEAT_COOLDOWN` (default equals `RAN_ALERT_COOLDOWN`), validation, docs rows (contract test)

## 2. Alert layer

- [x] 2.1 Offender table with bounded size, FIFO eviction and silence expiry; injectable clock
- [x] 2.2 Repeat cooldown in the cooldown filter path; shun deadline set when an alert is accepted
- [x] 2.3 `Sensor.Shunned(ip)` applying the ignore list; summary emission and shutdown flush

## 3. Accept path

- [x] 3.1 TCP skeleton check after PROXY handling and before `limiter.Acquire`
- [x] 3.2 HTTP traps use the same helper
- [x] 3.3 Metric `ran_connections_rejected_total{reason="shun"}` and gauge for active entries (bounded)

## 4. Tests and docs

- [x] 4.1 Unit tests with a fake clock: window, repeat threshold, class rules, ignored source, probe
- [x] 4.2 Trap-level test: brute force on a TCP trap, second connection closed without session log
- [x] 4.3 Bounded-table soak test with many unique sources
- [x] 4.4 Docs: relation to firewall bouncers, recommended settings, trade-off; AGENTS.md rule that new accept paths must call the sensor
- [x] 4.5 `go test -race ./...` in Docker, `GOARCH=386` vet, lint, `openspec validate --all`
