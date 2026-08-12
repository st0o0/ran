# Improve Session Logging

## Problem

Session logs are noisy, redundant, and lack context:

- `connect` and `disconnect` look identical — disconnect carries no duration or summary
- `protocol` and `trap` fields are always the same value
- `action` and `_msg` duplicate each other
- No `dest_port` — can't tell which listener was hit
- No session activity counters — can't distinguish scanner from attacker at a glance
- At default INFO level, every connect/disconnect pair produces two equally uninformative lines

## Changes

### 1. Remove `trap` logger field, keep `protocol` on session

Every trap constructor currently does `logger.With("trap", "smb")`. This produces a `trap` field identical to `protocol` on every session log. Remove the `logger.With("trap", ...)` call from all trap constructors. `protocol` remains as the session-level field.

### 2. Human-readable message with structured fields

Replace the bare action word as slog message with a human-readable summary. Structured fields stay for machine filtering.

| Action | Message format |
|---|---|
| connect | `smb connect from 196.188.252.69:1587` |
| disconnect | `smb disconnect from 196.188.252.69:1587 duration=36ms auth=0 cmd=0` |
| auth_attempt | `smb auth from 196.188.252.69:1587 user=CORP\admin` |
| command | `ssh command from 41.72.100.3:52001 cmd=ls -la` |
| payload | `dns payload from 185.220.101.5:44312 type=dns_query` |

### 3. Connect event → DEBUG level

Connect provides real-time visibility but doubles every session's log output. Move it to DEBUG. At the default INFO level, only disconnect (with full summary), auth_attempt, command, and payload are visible.

### 4. Enrich disconnect with duration and activity counters

Add counters to the `Session` struct that are incremented by `LogAuthAttempt`, `LogCommand`, and `LogPayload`. On disconnect, include:

- `duration_ms` — session duration in milliseconds
- `auth_attempts` — number of auth attempts during the session
- `commands` — number of commands logged
- `payloads` — number of payloads logged

### 5. Add `dest_port` to session

Pass the listener's port to `NewSession` so all session logs include `dest_port`. This distinguishes which trap instance was hit when the same protocol runs on multiple ports.

### 6. Session-scoped logger

Instead of repeating `protocol`, `session_id`, `source_ip`, `source_port` in every `LogXxx` call, create a child logger on the `Session` with those fields baked in. Individual log methods only add their specific extras.

## Scope

- `internal/trap/trap.go` — Session struct, all Log methods, NewSession signature
- `internal/trap/*.go` — all trap constructors (remove `logger.With("trap", ...)`) and handle methods (pass dest_port to NewSession)
- No config changes, no new dependencies
- Existing Loki queries filtering on `action` continue to work
- Queries filtering on `trap` must be migrated to `protocol`

## Out of scope

- Log format changes (JSON/text choice stays as-is)
- Log rotation or output targets
- GeoIP enrichment (already handled by Loki/Promtail pipeline)
- Alerting logic changes
