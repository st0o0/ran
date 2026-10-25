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

## Verified container facts

Spike run against `crowdsecurity/crowdsec:v1.8.1`, digest `sha256:0f2523fa61ef507f15d953045cface490cc880670c62f2755ced17524107f71a` (also published as `ghcr.io/crowdsecurity/crowdsec`). The pin lives in `internal/crowdsecprofile/version.go` (`TestedImage`); a renovate regex custom manager in `renovate.json` keeps tag and digest current, because the shared docker preset only scans Dockerfiles, compose files and workflows, not a Go constant.

- **LAPI only, no outbound traffic**: `DISABLE_AGENT=true` and `DISABLE_ONLINE_API=true` (the log shows "push and pull to Central API disabled"). `CROWDSEC_BYPASS_DB_VOLUME_CHECK=true` is required without a volume on `/var/lib/crowdsec/data`, otherwise the entrypoint prints "No volume mounted" and exits 0 without starting. The line `Error: no matches found` during startup (hub preparation) is harmless.
- **Machine registration**: `AGENT_USERNAME` and `AGENT_PASSWORD` register a machine at startup (`Machine 'ran' successfully added to the local API`), no `cscli machines add` needed. The image also registers its own machine `localhost`.
- **Bouncer registration**: `BOUNCER_KEY_<name>=<key>` registers a bouncer with that fixed key (`Registered bouncer for <name>`). The key is then used as `X-Api-Key` on `GET /v1/decisions?ip=<ip>`.
- **Profile mount**: a read-only single-file bind mount `-v <file>:/etc/crowdsec/profiles.yaml:ro` works; the entrypoint prestages the rest of `/etc/crowdsec` with `rsync --ignore-existing`, so the mounted file wins. `docker cp` into a not yet started container does not work because `/etc/crowdsec` does not exist before the first start.
- **Allowlist**: `cscli allowlists create <name> -d <description>` then `cscli allowlists add <name> <ip>`; `cscli allowlists check <ip>` confirms. The allowlist takes effect immediately, no restart. An alert for an allowlisted IP is dropped and not stored.
- **Readiness**: `GET /health` on the LAPI port returns 200 once the server listens (machine and bouncer are registered before that). `docker exec <c> cscli lapi status` also works. Startup takes a few seconds; the test polls `/health` for up to 120 seconds.
- **Port**: publish `-p 127.0.0.1::8080` and read the host port with `docker port <c> 8080/tcp`, so parallel runs never collide.
- **Reading decisions**: the bouncer endpoint returns a JSON array or `null`; each row has `duration` (remaining time as a Go duration string such as `2h59m59s`), `origin`, `scope`, `type`, `value`. `cscli decisions list -o json` shows the same rows grouped under alerts.
- **Reading alerts**: `cscli alerts list` hides alerts without an active decision (probe, allowlisted, expired). Use `-a`; `--ip` does not match them in this version, `--value <ip>` does: `cscli alerts list -a --value <ip> -o json --limit 0`.
- **Speed**: nothing to tune. The profile is evaluated synchronously in `POST /v1/alerts`, so a decision is visible right after the alert is accepted (about 0.4 seconds per alert including the test's polling). The whole test takes about 7 seconds plus container start.
- **Decisions accumulate**: every ban alert adds a new decision row; older rows are not replaced (after 7 alerts 7 rows exist, the longest one wins for the bouncer). The 168h cap therefore renews the ban with a fresh 168h row.
- **Observed escalation** (alert n, longest remaining ban at read time): 1h, 2h59m59s, 8h59m59s, 27h, 80h59m59s, 167h59m59s, 167h59m59s. This matches 1h, 3h, 9h, 27h, 81h, then the 168h cap from the sixth alert on.
- **Mutation checks** (both fail the integration test): with `min(168, ...)` (int literal) the sixth and seventh alert add a row that falls back to the base 1h, so the longest ban stays at 81h instead of reaching 168h; without `ran_noban` a following `Alert.Remediation == true` profile bans a probe for its own duration (4h in the test).
- **Profile parsing pitfall**: a trailing YAML document that contains only comments after a `---` separator made the following profile (appended by the test) silently not load. Keep comments inside a profile document, never in a document of their own.
