## Why

Operators scan their own hosts: uptime monitors, vulnerability scanners, health checks, an admin who mistyped a port. With a public source address, any of these classify as `probe`, `attack` or `scan` and may end up banned, including the operator's own monitoring. OpenCanary offers an ignore list; rán has no equivalent (CrowdSec allowlists apply only on the LAPI side and only to alerts without decisions).

## What Changes

- New `RAN_IGNORE_IPS`: comma-separated IPs and CIDRs (v4 and v6). Parsed and validated at startup; an invalid entry fails `check-config` and names the offending value.
- Sessions from an ignored source are still served, logged (with an `ignored` marker) and counted in connection metrics, but never alert, never feed the scan tracker and never enter the probe summary.
- New metric `ran_ignored_sessions_total{protocol}` and a pipeline stage `ignored` in `ran_crowdsec_pipeline_total`.
- The startup log states how many ranges are ignored.

## Capabilities

### New Capabilities

- `ignore-list`: source allow-list that suppresses alerts and classification state.

### Modified Capabilities

- `alert-classification`: ignored sources are excluded from scan tracking.
- `config`: `RAN_IGNORE_IPS` parsing and validation.

## Impact

- `internal/config/config.go`, `internal/alert/sensor.go` (check before `classify`), metrics, README (config row, contract test), tests.
- With PROXY protocol the check uses the address the trap sees, i.e. the header address.

## Non-goals

- No dynamic reload and no sync from CrowdSec allowlists (that belongs to the CrowdSec change).
- No effect on rate limiting: ignored sources still count against `RAN_MAX_PER_IP`.
- No hostname or ASN entries.
