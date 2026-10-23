## Why

Every attacker gets the same static ban duration regardless of whether they appear once or a hundred times. Repeat offenders walk back in after 4 hours with zero escalation. CrowdSec Profiles support `duration_expr` with `GetDecisionsCount()` to dynamically escalate bans — but ran's current self-contained decisions bypass this entirely because the embedded decision takes precedence. We should document how to leverage CrowdSec's built-in escalation while keeping ran's default-decision as a safe fallback for unconfigured installations.

## What Changes

- **README documentation**: Add a "Ban Escalation" section documenting CrowdSec Profile configuration for progressive and permanent bans, including ready-to-use YAML examples.
- **Config documentation**: Document that `RAN_CROWDSEC_BAN_DURATION` serves as the fallback duration when no CrowdSec Profile overrides it, and that Profiles can escalate dynamically.
- **No code changes required**: ran already pushes alerts with embedded decisions. CrowdSec Profiles can override these decisions server-side — ran's current behavior is the correct fallback.

## Capabilities

### New Capabilities

- `ban-escalation-guide`: Documentation and recommended CrowdSec Profile configurations for progressive ban escalation and permanent ban thresholds.

### Modified Capabilities

_(none — no spec-level behavior changes, ran continues to push self-contained decisions as before)_

## Impact

- **README.md**: New section with CrowdSec Profile examples
- **No code changes**: ran's alert push logic remains unchanged
- **No breaking changes**: Existing deployments without Profiles continue to work identically
- **CrowdSec dependency**: Escalation requires CrowdSec >= 1.4 (profiles with `duration_expr` support)
