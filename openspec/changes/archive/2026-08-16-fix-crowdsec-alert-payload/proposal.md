## Why

Every POST /v1/alerts to CrowdSec LAPI returns HTTP 500 because the alert JSON payload is missing the required `events` field. The `csAlert` struct has no `Events` field, so the marshalled JSON omits it entirely — CrowdSec rejects this during validation before any DB write (~250µs response). Secondary: `source.scope` uses `"ip"` instead of CrowdSec's canonical `"Ip"`. Zero alerts have ever been pushed successfully.

## What Changes

- Add the required `events` field to the CrowdSec alert payload, populated with trap-specific metadata (username, password, command, domain, etc.) so alerts carry useful forensic context
- **BREAKING**: Widen the `Alerter` interface from `Alert(ctx, ip, protocol)` to `Alert(ctx, ip, protocol, meta)` where `meta` is `map[string]string` — all trap call sites and tests must be updated
- Fix `source.scope` and `decisions[].scope` from `"ip"` to `"Ip"` to match CrowdSec's canonical casing
- Add `csEvent` and `csMeta` types to model the CrowdSec event structure

## Capabilities

### New Capabilities

(none)

### Modified Capabilities

- `crowdsec-alerter`: Add required `events` field to LAPI payload, widen `Alerter` interface to accept metadata, fix scope casing

## Impact

- `internal/alert/alerter.go` — interface signature change (breaking for all implementors)
- `internal/alert/crowdsec.go` — new types (`csEvent`, `csMeta`), payload construction in `push()`, scope casing fix
- `internal/alert/crowdsec_test.go` — updated interface calls, new payload assertions for events and scope
- All trap files in `internal/trap/` (~20 files) — each `Alert()` call site adds a metadata map with trap-specific context
