## Why

Operators configure `ran` through about 40 `RAN_*` variables plus per-trap ones, and the combinations that matter (PROXY protocol behind a reverse proxy, CrowdSec, UDP traps that never alert) are easy to get wrong. A real deployment lost the client IPs of its proxied HTTP trap for a week because the global PROXY switch could not be used. A guided builder on the documentation site, modelled on the njord config builder, turns "read 270 lines of reference" into "pick a scenario, copy the file".

## What Changes

- A settings register generated from Go: `config.Settings` (name, kind, default, group, summary, dependencies) is the single source for `docs/data/settings.generated.json`, written by `internal/tools/docgen` next to the trap table. Tests fail when the register and the variables `Load` reads differ, and when the generated file is stale.
- A builder page `/builder` (Vue component in the VitePress theme, no server): scenario first (direct, behind a reverse proxy, shared network namespace, with CrowdSec), then traps by group, then the settings of the chosen features.
- Export as an env file, a `docker-compose.yml` and a `docker run` line. Only values that differ from the default are written. Per-scenario hints (Caddy `proxy_protocol v2`, trusted ranges) are shown next to the output.
- Live warnings that mirror the Go validation (PROXY without trusted peers, UDP trap in the PROXY list, a PROXY trap that is not enabled, wide port ranges, UDP traps never alert).
- Share and restore through the URL hash, and import of an existing env file.
- Pure logic (state, validation, serializers) lives in plain TypeScript modules with unit tests (vitest), the Vue file only renders.

## Capabilities

### New Capabilities

- `config-builder`: the settings register and the builder page.

## Impact

- `internal/config` (register and drift tests), `internal/tools/docgen` (writes the JSON), `docs/.vitepress/theme/builder/*`, `docs/builder.md`, `docs/package.json` (vitest), CI docs job (runs the builder tests), `AGENTS.md` note, contract test (every variable must be in the register).
- No runtime change to the sensor.

## Non-goals

- No server side, no storage, no telemetry. The page never sends a configuration anywhere.
- No password or secret handling beyond a placeholder: the builder never asks for the CrowdSec password, it writes `CHANGE_ME` and a note.
- No Kubernetes or Helm output in this change.
