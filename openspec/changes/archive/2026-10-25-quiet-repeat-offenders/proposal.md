## Why

On a host whose trap ports are open to the internet and whose bans are enforced only by a reverse proxy bouncer, a banned source keeps hammering the traps. Measured on such a host:

- ran was the loudest container: about 460 000 log lines in 24 hours, more than any other service on the host.
- 20 of 2262 sources (under 1 percent) produced 62 percent of those lines. One source made about 57 000 RDP login attempts in about four hours (roughly four per second, three log lines each) and alone accounted for 37 percent of the day's volume.
- About 320 sources were active on 5 or more of 8 days. One of them caused 24 alerts in 3 days.
- At the top escalation step (168h) further alerts change nothing except renewing the ban, so a persistent bot keeps its ban alive forever and the escalation ladder never plays out as designed.

The profile ladder assumes that a ban takes effect where the offender sends its traffic. Today ran keeps serving the offender during its own ban window. That wastes CPU and log storage and produces thousands of near-identical credential samples with no new information.

## What Changes

All behavior is opt-in; the defaults reproduce today's behavior.

- **Shun (`RAN_SHUN=on`)**: after ran has sent an alert for a source (class `attack` or `scan`), new TCP connections from that source are closed immediately at accept time for the shun window, without a session, a goroutine, a banner or per-connection log lines. The source looks like a host protected by a firewall rule. The window equals the alert cooldown, so when it ends the next attack produces the next alert and the CrowdSec ladder advances as designed.
- **Repeat cooldown (`RAN_REPEAT_AFTER`, `RAN_REPEAT_COOLDOWN`)**: after `RAN_REPEAT_AFTER` alerts (default 5, the length of the documented ladder) for a source and class, the cooldown (and with shun on, the shun window) becomes `RAN_REPEAT_COOLDOWN` (default equal to `RAN_ALERT_COOLDOWN`, so no change until set; the docs recommend 12h). Alert volume for persistent sources drops without slowing escalation.
- **Summary instead of noise**: when a shun window ends (or the entry is evicted), one log line `shun summary` reports the source, the suppressed connection count, the protocols involved (bounded) and the window. Metric `ran_connections_rejected_total{reason="shun"}` counts suppressed connections; no client data in labels.
- Ignored sources (`RAN_IGNORE_IPS`) are never shunned. `probe` class sessions never trigger a shun. UDP traps are untouched.
- Docs: how this relates to a firewall bouncer (the same loop, enforced inside ran), recommended settings, and the trade-off.

## Capabilities

### New Capabilities

- `repeat-offenders`.

## Impact

- `internal/alert` (offender table next to the cooldown filter, shun query), `internal/trap/tcpserver.go` and the HTTP trap accept path (check before the session is created), `internal/config`, metrics, docs, tests and a fuzz-free soak test of the bounded tables.
- Expected effect on the measured host, as an estimate: most of the 62 percent of lines from the top sources disappear and the alert rate of persistent sources drops by about three quarters with `RAN_REPEAT_COOLDOWN=12h`.

## Non-goals

- No firewall or nftables handling (ran stays rootless and single binary); a firewall bouncer remains a valid alternative.
- No query of CrowdSec decisions: ran mirrors its own alerts locally and does not know about decisions made for other reasons.
- No shun for sources that never alerted, no probabilistic sampling, no summary logging for sources that are not shunned.
