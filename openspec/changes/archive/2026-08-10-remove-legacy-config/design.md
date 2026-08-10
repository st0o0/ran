## Context

The ran honeypot Config struct was originally built with explicit fields per trap (SSH/HTTP/MySQL). When 24 new traps were added, a generic system (`RAN_TRAPS`, `Addrs map[string]string`, `TrapAddr()`) was introduced. The original three traps were never migrated, leaving dual code paths in `Load()` and dual fields in `Config`.

## Goals / Non-Goals

**Goals:**
- Single config path for all traps via `RAN_TRAPS` and `TrapAddr()`
- Remove 6 legacy fields from Config struct
- Make SSH host key path configurable via `RAN_SSH_HOST_KEY_PATH`
- Simplify `Load()` by removing legacy parsing and sync blocks

**Non-Goals:**
- Backward compatibility shim for `RAN_SSH`/`RAN_HTTP`/`RAN_MYSQL` env vars
- Refactoring the `envReader` or other config internals
- Changing behavior of any trap beyond its address/key-path source

## Decisions

### 1. No deprecation period for legacy env vars

Remove `RAN_SSH`, `RAN_HTTP`, `RAN_MYSQL` immediately rather than adding a deprecation warning. **Rationale**: This is an internal project with controlled deployments. The `RAN_TRAPS` system has been available since the trap registry was added. A deprecation period adds code complexity for no real benefit. Update error message in the "no traps enabled" check to reference only `RAN_TRAPS`.

### 2. SSHHostKeyPath as a Config field

Add `SSHHostKeyPath string` to Config, loaded from `RAN_SSH_HOST_KEY_PATH` with default `/data/ssh_host_key`. **Rationale**: The hardcoded constant in `ssh.go:23` prevents customizing the key path in different environments. Following the existing pattern of env-var-driven config keeps it consistent. Alternative considered: command-line flag -- rejected because ran uses env vars exclusively.

### 3. Trap code uses TrapAddr() directly

Each trap file calls `t.cfg.TrapAddr("<proto>")` instead of accessing a dedicated field. **Rationale**: This is already the pattern for all 24 newer traps. No wrapper or helper needed.

## Risks / Trade-offs

- **[Breaking env vars]** Deployments using `RAN_SSH=on` will fail on upgrade. -> Mitigation: Error message guides users to `RAN_TRAPS`. Docker Compose / deployment configs are in-repo and updated in the same change.
- **[Test churn]** Tests referencing legacy fields need updating. -> Mitigation: Straightforward find-and-replace; no behavioral changes in tests.

## Migration Plan

1. Update deployment configs (`docker-compose.yml`, `.env.example` if present) to use `RAN_TRAPS` before merging
2. Rollback: revert the commit; legacy fields are restored immediately
