## Why

Every rán instance presents the same fixed banners (`OpenSSH_9.6`, MySQL `8.0.36`, Apache `2.4.62`, a fixed SMTP name). A scanner that fingerprints honeypots can recognize all instances at once, and a fleet that looks identical is easy to filter. Per-trap class metadata is also missing for some single-request traps.

## What Changes

- Banner profiles: each version string comes from a small built-in set of plausible values per trap, chosen once at first start from a seed that is persisted (`/data/fingerprint_seed`, ephemeral fallback), so an instance stays stable across restarts but instances differ.
- `RAN_FINGERPRINT=fixed|seeded` (default `seeded`; `fixed` keeps the current values for people who parse banners).
- Per-trap class meta (`kind`) for the seven single-request traps (`vnc`, `rdp`, `oracle`, `mqtt`, `modbus`, `minecraft`, `adb`), so CrowdSec profiles can distinguish them.

## Capabilities

### Modified Capabilities

- `trap-ssh`, `trap-mysql`, `trap-http`, `trap-smtp`, `trap-elasticsearch` banners; `alert-classification` meta.

## Impact

- A small `fingerprint.go` with the seed and tables, trap constructors, README (banner notes, upgrade note: fingerprints change once). Tests must not hard-code banner strings.

## Non-goals

- No claim to defeat fingerprinting (the README stays honest about that).
- No random per-connection banners.
- No change of protocol behavior.
