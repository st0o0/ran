## 1. Config Extension

- [x] 1.1 Add CrowdSec fields to `Config` struct: `CrowdSec bool`, `CrowdSecURL string`, `CrowdSecAPIKey string`, `CrowdSecBanDuration time.Duration`
- [x] 1.2 Add env var parsing in `Load`: `RAN_CROWDSEC` (toggle), `RAN_CROWDSEC_URL`, `RAN_CROWDSEC_API_KEY`, `RAN_CROWDSEC_BAN_DURATION` (duration, default `4h`, `0` = permanent)
- [x] 1.3 Add validation: when `RAN_CROWDSEC=on`, URL and API key are required
- [x] 1.4 Add config tests for CrowdSec vars: enabled with all vars, missing URL, missing key, custom duration, permanent (`0`)

## 2. Metrics Extension

- [x] 2.1 Add `ran_crowdsec_alerts_total{protocol,status}` counter to `Metrics` struct and register it

## 3. Alerter

- [x] 3.1 Create `internal/alert/alerter.go` with `Alerter` interface (`Alert(ctx, ip, protocol)`) and `NoopAlerter` implementation
- [x] 3.2 Create `internal/alert/crowdsec.go` with CrowdSec LAPI client: buffered channel (cap 256), single worker goroutine, `POST /v1/alerts` with `X-Api-Key` header, self-contained ban decisions, per-protocol scenario names (`custom/ran-{protocol}-trap`), graceful shutdown drain (5s timeout)
- [x] 3.3 Create `internal/alert/crowdsec_test.go` with tests: alert JSON format, channel drop on overflow, graceful drain, success/failure metrics, permanent vs timed ban duration

## 4. Trap Wiring

- [x] 4.1 Add `Alerter` parameter to `NewSSH`, `NewHTTP`, `NewMySQL` constructors and call `alerter.Alert()` on every auth_attempt
- [x] 4.2 Update `cmd/ran/run.go` to create CrowdSec alerter (or noop) based on config, pass to all traps, and shut down alerter on exit
- [x] 4.3 Update existing tests to pass a `NoopAlerter` where constructors now require one

## 5. Documentation

- [x] 5.1 Update `README.md` with CrowdSec configuration section (env vars, setup, scenario names)
