## Why

Rán captures attacker credentials but currently does not act on them. CrowdSec integration enables instant bans: when an attacker hits any trap, Rán pushes an alert to CrowdSec's Local API, which propagates a ban decision to the Caddy bouncer — blocking the attacker across all sites within milliseconds.

This is the fastest path to protection. The trade-off (coupling to CrowdSec LAPI) is minimized by using an `Alerter` interface, keeping the HTTP client dependency-free (no CrowdSec SDK), and making the feature fully optional (`RAN_CROWDSEC=off` by default).

## What Changes

- Add `internal/alert/alerter.go` with `Alerter` interface and no-op implementation
- Add `internal/alert/crowdsec.go` with CrowdSec LAPI push client (buffered channel + worker goroutine)
- Add CrowdSec config env vars: `RAN_CROWDSEC`, `RAN_CROWDSEC_URL`, `RAN_CROWDSEC_API_KEY`, `RAN_CROWDSEC_BAN_DURATION`
- Add `ran_crowdsec_alerts_total{protocol,status}` Prometheus counter
- Wire alerter into all three traps (call on every `auth_attempt`)
- Add separate CrowdSec scenarios per trap protocol: `custom/ran-ssh-trap`, `custom/ran-http-trap`, `custom/ran-mysql-trap`

## Capabilities

### New Capabilities
- `crowdsec-alerter`: Push alerts to CrowdSec LAPI with self-contained ban decisions, non-blocking via buffered channel, per-protocol scenario naming

### Modified Capabilities
- `config`: Add CrowdSec env vars (`RAN_CROWDSEC`, `RAN_CROWDSEC_URL`, `RAN_CROWDSEC_API_KEY`, `RAN_CROWDSEC_BAN_DURATION`)
- `metrics`: Add `ran_crowdsec_alerts_total{protocol,status}` counter
- `trap-ssh`: Call alerter on auth_attempt
- `trap-http`: Call alerter on auth_attempt
- `trap-mysql`: Call alerter on auth_attempt

## Impact

- New package `internal/alert/`
- Modified `internal/config/config.go` (new env vars)
- Modified `internal/metrics/metrics.go` (new counter)
- Modified `internal/trap/ssh.go`, `http.go`, `mysql.go` (alerter calls)
- Modified `cmd/ran/run.go` (alerter creation + injection)
- Updated `README.md` with CrowdSec documentation
