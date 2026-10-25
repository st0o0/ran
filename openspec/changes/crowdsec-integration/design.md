## Profile file

Three profiles, in this order:

1. `ran_scan`: `Alert.GetScenario() startsWith "custom/ran-" && Alert.Events[0].GetMeta("class") == "scan"`, ban, `on_success: break`.
2. `ran_attack`: same filter for `attack`.
3. `ran_noban`: `Alert.GetScenario() startsWith "custom/ran-"`, no `decisions`, `on_success: break`. It catches every other class so no later profile (for example a default `Remediation == true` ban) acts on a probe.

`scan` and `attack` share the formula; the docs keep the note on how to give scanners a longer ban. The profile contains no `Remediation == true` fallback: that is the operator's own policy and would hide the effect of `ran_noban`.

`duration_expr` pitfalls (lowercase `min`, float literal, `%.0f`) are asserted by the integration test through the observed durations, not only by `crowdsec -t`, which compiles the expression but does not catch the formatting fallback.

## Integration test

- Image: `crowdsecurity/crowdsec`, pinned by tag and digest; LAPI only (agent disabled, online API disabled so CI sends no CAPI traffic).
- Setup through the image's environment variables and `cscli` in the container (machine and bouncer registration). The exact variable names and the profile mount path (`/etc/crowdsec/profiles.yaml`) are verified in the first task, not assumed.
- The test drives the production `CrowdSecAlerter` against the container URL (not a hand-built JSON body), so the wire format is covered. Decisions are read with `GET /v1/decisions` and the bouncer key (`X-Api-Key`).
- Durations are compared with a tolerance (the LAPI reports the remaining time), for example 1h within 2 minutes, 3h within 2 minutes.
- Docker is required: the test skips with a clear message when `RAN_CROWDSEC_IT` is not set, so `go test ./...` stays green on hosts without Docker. CI sets it.
- Local run: `RAN_CROWDSEC_IT=1 go test -tags crowdsec ./internal/alert/ -run CrowdSecIntegration`.

## Drift guard

`docs/crowdsec-profile.generated.md` is produced by docgen from the embedded file (fenced `yaml`). The existing docgen drift test covers it. The test and the docs therefore always use the shipped bytes.

## Risks

- The test depends on a container image and some seconds of startup; the workflow has a timeout and retries the readiness probe, not the assertions.
- A CrowdSec release can change profile semantics; that is exactly what the pinned tag plus a renovate PR is meant to surface.
