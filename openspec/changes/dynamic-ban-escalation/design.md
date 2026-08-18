## Context

ran pushes self-contained ban decisions to CrowdSec LAPI with a static duration (default 4h). Every attacker gets identical treatment regardless of history. CrowdSec Profiles support `duration_expr` with helper functions like `GetDecisionsCount()` to dynamically adjust ban durations based on prior decisions for the same IP — but this capability is undocumented for ran users.

ran's current architecture already supports this: the embedded default decision acts as a fallback, while CrowdSec Profiles can override decision parameters server-side. No code change is needed — only documentation.

## Goals / Non-Goals

**Goals:**
- Document how to configure CrowdSec Profiles for progressive ban escalation with ran
- Provide ready-to-use Profile YAML examples (escalating + permanent threshold)
- Explain the interaction between ran's default decision and CrowdSec Profiles

**Non-Goals:**
- Changing ran's alert push logic (it already works correctly for this use case)
- Building escalation logic into ran itself (Weg 1 — kept as future fallback)
- Writing a custom CrowdSec Scenario or Parser (not needed with LAPI push)
- Supporting CrowdSec versions older than 1.4 (required for `duration_expr`)

## Decisions

### Decision: Documentation-only change, no code modification

ran already pushes alerts with embedded decisions. CrowdSec Profiles process all incoming alerts — including LAPI-pushed ones — and can override the decision duration via `duration_expr`. The default decision serves as a safe fallback for installations without a Profile.

**Alternative considered:** Remove the embedded decision from ran and rely entirely on Profiles. Rejected because this would be a breaking change — existing deployments without Profiles would stop banning entirely.

**Alternative considered:** Build escalation logic into ran with an in-memory IP tracker (Weg 1). Rejected for now because CrowdSec already has this capability built in. Kept as fallback option if Profile-based escalation proves insufficient.

### Decision: Two-profile escalation pattern

The recommended configuration uses two CrowdSec Profiles in order:

1. **Permanent ban profile** (filter: decision count >= threshold) — catches persistent offenders first
2. **Escalation profile** (filter: all ran alerts) — exponentially increasing duration for everyone else

Profile ordering matters: CrowdSec evaluates profiles top-to-bottom and stops at the first `on_success: break`. The permanent profile must come first.

**Alternative considered:** Single profile with a ternary expression capping at permanent. Rejected because two profiles are easier to read, modify independently, and disable selectively.

### Decision: Exponential backoff formula

Recommended formula: `4 * (3 ^ count)` hours.

| Hit # | Count | Duration | Human |
|-------|-------|----------|-------|
| 1 | 0 | 4h | 4 hours |
| 2 | 1 | 12h | 12 hours |
| 3 | 2 | 36h | 1.5 days |
| 4 | 3 | 108h | 4.5 days |
| 5 | 4 | 324h | 13.5 days |

This escalates aggressively enough to deter repeat offenders while giving transient scanners a reasonable cooldown. Users can adjust the base (4), multiplier (3), or switch to linear escalation.

### Decision: Document in README under existing CrowdSec section

The ban escalation guide belongs directly in README.md under the existing "CrowdSec" configuration section. It's operational guidance, not a separate concept.

## Risks / Trade-offs

- **CrowdSec decision database purge resets counters** → Document that `GetDecisionsCount()` depends on CrowdSec's decision retention. Users should configure appropriate retention windows (`cscli config show` → `db_config.flush.max_age`).
- **Profile misconfiguration silently drops bans** → Provide a verification command (`cscli decisions list`) in the documentation so users can confirm escalation is working.
- **CrowdSec version requirement** → `duration_expr` requires CrowdSec >= 1.4. Document this prerequisite clearly.
- **ran's default decision may conflict with Profile decision** → CrowdSec Profiles override embedded decisions when they match. Document this interaction explicitly so users understand the precedence.

## Open Questions

_(none — all decisions resolved during exploration)_
