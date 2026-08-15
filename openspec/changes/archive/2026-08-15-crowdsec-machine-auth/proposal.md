## Why

ran authenticates to CrowdSec LAPI using a bouncer API key (`X-Api-Key` header), but pushes alerts via `POST /v1/alerts` — an endpoint designed for machine-authenticated clients. This is the wrong auth level: bouncer keys are meant for reading decisions, not pushing alerts. Switching to proper machine-login authentication (machine_id + password → JWT) aligns ran with the CrowdSec security model and removes the need to provision bouncer keys for a non-bouncer use case.

## What Changes

- **BREAKING**: Replace `RAN_CROWDSEC_API_KEY` env var with `RAN_CROWDSEC_MACHINE_ID` and `RAN_CROWDSEC_PASSWORD`
- Authenticate via `POST /v1/watchers/login` to obtain a JWT token
- Use `Authorization: Bearer <token>` header instead of `X-Api-Key` for alert pushes
- Add proactive background token refresh (at 80% of token lifetime) with exponential backoff on failure
- Add 401-retry in push as safety net for edge cases (clock skew, token revocation)
- `NewCrowdSec()` performs an eager login and returns an error on failure (fail-fast)
- Machine registration remains out-of-band via `cscli machines add`

## Capabilities

### New Capabilities

_None — this change modifies existing capabilities._

### Modified Capabilities

- `crowdsec-alerter`: Authentication mechanism changes from API-key to machine-login with JWT token lifecycle management
- `config`: CrowdSec env vars change from `RAN_CROWDSEC_API_KEY` to `RAN_CROWDSEC_MACHINE_ID` + `RAN_CROWDSEC_PASSWORD`

## Impact

- **Config**: `RAN_CROWDSEC_API_KEY` removed, two new env vars required — breaking change for existing deployments
- **Code**: `internal/alert/crowdsec.go` — new login/token-refresh logic, modified push auth header
- **Code**: `internal/config/config.go` — new fields, updated validation
- **Code**: `cmd/ran/run.go` — `NewCrowdSec` signature change (now returns error)
- **Tests**: All CrowdSec tests need updating for new auth flow
- **Docs**: README CrowdSec section needs updating
- **Docker Compose**: Example config in README needs new env vars
