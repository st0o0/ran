## Why

Escalation only works when a CrowdSec profile matches what rán sends. Today the profile is prose in the docs, and "verified against v1.8.1" is a manual statement: nothing in CI fails when rán's alert shape or the example profile drifts apart (the 0.3.x embedded-decision bug and the `min(168, ...)` int pitfall were both found by hand). The example in the docs also lacks the guard that a real deployment needs: without a `probe` profile, a generic `Remediation == true` default profile bans probes too.

## What Changes

- The example profile becomes a file in the repo (`internal/crowdsecprofile/profiles.yaml`, embedded with `go:embed`): `ran_scan`, `ran_attack` and `ran_noban` (any other `custom/ran-*` alert, for example `probe`, stops evaluation without a decision, so a later catch-all profile cannot ban it). Escalation `min(168.0, 3 ^ GetDecisionsCount(Alert.GetValue()))` hours, 1h base.
- New subcommand `ran crowdsec-profile` prints the embedded file to stdout, so operators get the profile that matches their binary (`docker run --rm ghcr.io/st0o0/ran crowdsec-profile > profiles.yaml.local`). The docs include the same file through the docgen tool (`docs/crowdsec-profile.generated.md`, drift test like the trap table), so docs, binary and CI test cannot diverge.
- New integration test (build tag `crowdsec`, own workflow `crowdsec-it.yml`, runs on pull requests that touch `internal/alert`, `internal/crowdsecprofile` or the workflow, on a schedule and on demand): starts the official `crowdsecurity/crowdsec` image as LAPI only with the embedded profile mounted, registers a machine and a bouncer key, pushes alerts through the real `CrowdSecAlerter`, and asserts through the bouncer endpoint that
  - a `scan` and an `attack` alert create a ban decision with origin `crowdsec` for the source IP,
  - a second alert for the same IP creates a longer ban (1h, then 3h, within tolerance),
  - a `probe` alert creates no decision,
  - an alert for an IP in a LAPI allowlist creates no decision.
  The CrowdSec image tag is pinned (renovate keeps it current), so a CrowdSec upgrade that breaks profile syntax or semantics fails CI instead of production.
- Docs: `docs/crowdsec.md` states the tested CrowdSec version from the pinned tag, documents `ran_noban` and the interplay with a generic `Remediation == true` profile, and the new subcommand. The README section is updated the same way.

## Capabilities

### New Capabilities

- `crowdsec-profile`.
- `crowdsec-integration-test`.

## Impact

- New `internal/crowdsecprofile` package, `cmd/ran` subcommand, docgen output, integration test and workflow, docs and README, `AGENTS.md` (how to run the integration test locally, which facts are now test-backed).
- No change to the alert wire format or to existing environment variables. The default `go test ./...` is unaffected (build tag).

## Non-goals

- No CrowdSec Hub collection (profiles are local files; the Hub carries parsers, scenarios and AppSec rules).
- No skipping of alerts for IPs the LAPI already bans: the cooldown renews bans on purpose and `GetDecisionsCount` counts alerts.
- No LAPI allowlist query for the ignore list (separate spike: needs a bouncer key, unverified) and no second sink (AbuseIPDB). Both stay in `todo.md`.
- The profile does not cover Caddy, AppSec or other scenarios; operators combine it with their own profiles. The docs state that the rán profiles must come before generic ones.
