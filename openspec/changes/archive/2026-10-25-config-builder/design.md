## Context

njord ships a Vue config builder whose feature register is a hand-written JSON file. That register can drift from the code. `ran` already generates the trap table from `config.DefaultPorts`; the builder extends that idea to all settings.

## Decisions

1. **Register in Go, JSON generated.** `config.Settings` is a slice of `Setting{Name, Kind, Default, Group, Summary, Requires, Scenario}`. Kinds: `bool`, `int`, `duration`, `string`, `enum`, `list`, `addr`. `docgen` writes `docs/data/settings.generated.json` (sorted, stable). The builder imports it; nothing in the page is typed by hand except labels of scenarios.
2. **Drift is a test failure.** (a) every variable `Load` reads (the `knownEnvVars` helper) is in `Settings` or in an explicit `per-trap` family entry, and every register entry is read by `Load`; (b) defaults in the register equal the defaults `Load` produces for an empty environment (compared by loading and formatting, not by string equality of code); (c) the generated JSON equals the file on disk.
3. **Per-trap families.** Variables like `RAN_<PROTO>_...` are one register entry with a `family` field and the list of traps it applies to, so the builder renders them under the trap and the contract test still passes.
4. **Validation mirrored, not reimplemented blindly.** The Go validation is the authority. The builder repeats a small, listed set of rules in TypeScript (PROXY needs trust, UDP traps cannot use PROXY, listed PROXY trap not enabled, port conflicts, `RAN_BURST >= RAN_RATE`). A shared test vector file `docs/data/builder-cases.json` (input env, expected error or warning id) is generated from Go cases and replayed by both the Go tests (through `config.Load`) and the vitest suite, so the two cannot disagree silently.
5. **Scenario first.** Scenarios are presets over the register: `direct`, `reverse-proxy` (PROXY for the listed traps, trusted ranges), `shared-namespace` (trust `127.0.0.1,::1`), `crowdsec` (adds the CrowdSec variables and, once `crowdsec-integration` ships, the profile). A scenario only sets values; the user can change everything afterwards.
6. **Delta-only export** like njord: a value equal to the default is omitted. Output formats: env file, Compose (ports derived from the enabled traps and their transports, `cap_drop: [ALL]`, read-only root, the data volume), `docker run`.
7. **State in the URL hash**, base64url of a compact JSON (only non-default values) using `TextEncoder` so non-Latin-1 input cannot throw. Decoding failures fall back to defaults. No localStorage.
8. **Secrets.** The CrowdSec password and machine id are never taken as input. Output uses `CHANGE_ME` and a visible note.
9. **Testing.** Logic in `builder/*.ts` is framework free; vitest runs in the docs CI job. The Vue component has no logic beyond binding.

## Risks

- Large register makes the page long. Mitigation: scenario first, advanced settings collapsed, search field.
- A TypeScript rule drifting from Go. Mitigation: shared case vectors (decision 4).
- New dependency (vitest). Mitigation: dev dependency only, pinned, renovate pnpm preset covers it.
