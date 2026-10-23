## Context

CrowdSec LAPI evaluates `profiles.yaml` only for alerts without embedded decisions. ran embeds one, so profile `duration_expr` and `GetDecisionsCount` never run, and the embedded 4h decision always wins. Re-pushes after the decision-cache or dedup window add one decision row per push; `GetDecisionsCount` counts all rows for the IP, including expired ones, so counts reflect traffic volume rather than distinct episodes. Logging is one line per session, dominated by VNC probes at scale.

Variante Y (decided by the operator): ran is a sensor. It classifies, rate-limits per episode, and pushes alerts without decisions and with `remediation: true`; profiles decide.

## Goals / Non-Goals

**Goals:** profiles actually run; escalation counts episodes; classification usable in profile filters; far less log volume; minimal beginner setup (copy one profiles.yaml).

**Non-Goals:** the per-trap fixes (follow-up change), `security-hotfix` items, ran-side bans.

## Decisions

### Alert shape
`decisions: []`, `remediation: true`, `simulated: false`, scenario `custom/ran-<proto>-trap`, `capacity: 0`, `leakspeed: "0"`, `Source{Scope:"Ip", Value:ip}`. ran MUST set both `Source.IP` (Alloy geo enrichment) and `Source.Value`: an alert with only `source.ip` and an empty `value` creates no decision ("invalid ip address ''"). The profile-created decision has origin `crowdsec`, not `ran`. `remediation: false` would create the alert only. One event with meta: `class`, `protocol`, `dest_port`, `auth_attempts`, `commands`, `payload_bytes`, plus existing trap meta. Profiles MUST select with the event form `Alert.Events[0].GetMeta("class") == "attack"`: `Alert.GetMeta("class")` reads only alert-level meta and matches nothing when meta lives on the event only (verified against CrowdSec v1.8.1). A `probe` alert matches no profile, hence no ban.

### Classification
- attack: auth attempts > 0, or commands > 0, or payload bytes > 0.
- probe: connect and banner only.
- scan: >= 3 distinct TCP trap protocols from one IP within 10 minutes. UDP never counts (spoofable, and already excluded from alerting by `security-hotfix`).

`Session` already counts authAttempts, commands and payloads; payload bytes is a new counter. `SessionEnd` re-classifies from the counters, so command-logging traps (redis, memcached, imap, irc, VNC after an auth attempt) end as `attack` even without a mid-session alert; redis, memcached, imap and irc also alert on the first command with only the command name as meta (max 32 bytes). Pure fingerprinting stays `probe`: Elasticsearch plain GET requests without a body (`/`, `/_cluster/health`, other GETs) and Minecraft server-list pings (next_state 1); both are logged with `Session.Log`, which does not count. Elasticsearch counts a command for any non-GET method or any request with a body; Minecraft counts payload only for a login with a player name. Modbus and ADB stay attack on a single request (known follow-up).

### Meta and batch bounds
Trap meta is client controlled, so before queueing it is bounded: values are cut to 256 bytes at a rune boundary, keys to 64 bytes, control characters become spaces, and at most 32 keys survive (sensor keys always, surplus trap keys dropped in sorted order). A batch also flushes early once its estimated JSON size exceeds 512 KiB. When a push fails, the cooldown slots of the batch are released (stage `released`), so the attacker is reported again after the LAPI recovers.

### Sensor lifecycle
The sensor maintenance ticker always runs (scan tracker cleanup even with `RAN_PROBE_SUMMARY_WINDOW=0`). After `Close` the probe log rejects records, so a straggler session is logged per session instead of creating an orphan summary. `Sensor.Alert` ignores non-TCP sessions as defense in depth. Probe log keys are unmapped IPs.

Shutdown uses one shared deadline of 9s (below Docker's 10s stop grace period). Traps and the metrics server stop in parallel within 4s; the sensor then closes the sink with the remaining time. The CrowdSec drain is capped at the flush timeout (5s: one flush may do two posts plus a re-login) and at the shared deadline. If `Close` interrupts a failure hold, the first pending batch gets one final attempt of at most 2s; if it succeeds the rest drains normally, otherwise the rest fails without posting. If every trap returns while nothing asked to stop, `run` returns an error (exit code 1).

### Scenario naming
Keep `custom/ran-<proto>-trap` for all classes, including scan (the scan alert uses the protocol that crossed the threshold). Rejected `custom/ran-scan`: it would break existing dashboards and scenario filters; the `class` meta is enough.

### Cooldown replaces cache and dedup
`RAN_ALERT_COOLDOWN` (default 4h) keyed by IP plus class: the first qualifying session sends an alert, later ones in the window only update logs and metrics. A move to a higher class (probe to attack, attack to scan) bypasses the cooldown once. The map is capped (same cap policy as `security-hotfix`) with oldest-first eviction. Default 4h matches the base profile duration, so a continuous attacker produces about one decision row per ban period and `GetDecisionsCount` counts episodes.

### Aggregated logging
Per IP and 60s window, one summary line (sessions per protocol, class counts, totals) replaces per-session connect/disconnect lines for probe sessions. Attack sessions keep full lines (credentials and commands are the research value). Metrics are updated per session as before, so dashboards are unaffected.

### Metrics
`ran_connections_total`, `ran_credentials_captured_total`, `ran_active_sessions`, `ran_session_duration_seconds` and `ran_crowdsec_alerts_dropped_total` keep names and labels. `ran_crowdsec_pipeline_total` keeps `received`, `queued`, `sent`, `failed`, `dropped` and adds `released`; `cached` and `deduplicated` are replaced by `cooldown` and `filtered` (class not in `RAN_BAN_ON`). Dashboards querying the old stages must be updated. No `class` label is added to existing metrics (cardinality, compatibility).

### Config
Removed: `RAN_CROWDSEC_BAN_DURATION`, `RAN_CROWDSEC_DECISION_CACHE`, `RAN_CROWDSEC_DEDUP_WINDOW`. Added: `RAN_BAN_ON`, `RAN_ALERT_COOLDOWN`. `RAN_CROWDSEC_BATCH_INTERVAL` and `RAN_CROWDSEC_BATCH_SIZE` stay. Removed variables found in the environment log a one-time warning instead of failing startup.

### Example profiles (README)
attack: base 1h, key `filters:` (list; the singular `filter:` makes the LAPI exit with "field filter not found in type csconfig.ProfileCfg"), `duration_expr: Sprintf('%.0fh', min(168.0, 3 ^ GetDecisionsCount(Alert.GetValue())))`. The first alert gives 1h (3^0); `duration_expr` overrides the profile duration and the newest decision replaces the older one. Pitfalls verified on v1.8.1: capital `Min` does not compile and CrowdSec exits fatally ("unknown name Min"); lowercase `min` with `%dh` silently falls back to the base duration ("%!d(float64=...)") because `3 ^ n` is a float. scan: the same formula as attack (operators may use a harder formula for scan, noted in the README). probe: no profile, hence no ban. Profiles use `on_success: break`, scan profile first. The profile syntax (keys, expression and decisions) was verified in a CrowdSec v1.8.1 container; the key names match the operator profiles file.

## CrowdSec behaviors to document
- Alerts without decisions are still forwarded to CAPI (custom scenarios) unless `simulated: true`. Operators who do not want to share must disable CAPI sharing on the CrowdSec side.
- Allowlists apply to alerts without decisions: such an alert for an allowlisted IP is dropped (not stored). An alert with an embedded decision is still ban-listed, which is why the redesign is needed.
- `simulated: true` alerts create a decision flagged simulated that is not in the bouncer stream (not enforced). CAPI sharing of simulated alerts was not tested.
- Machine credentials stay required.
- `GetDecisionsCount` needs `db_config.flush.max_age` and `max_items` sized to cover the longest escalation step (168h) at the alert rate; see Risks.

## Risks / Trade-offs
- No profile means no ban: a silent regression for 0.3.x users. Mitigation: migration notes and a startup log line stating that ran does not ban by itself.
- Alert history bounds escalation memory. `db_config.flush.max_items` deletes only alerts without an active decision; a deleted alert drops out of `GetDecisionsCount`, which lowers or resets the escalation level (observed 27h instead of 81h, and a restart at 1h). Active bans are never expired early. Operators MUST size `max_items` (and `max_age`) to cover 168h at their alert rate. In the real deployment ran creates about 4000 alerts per day before this change; the per-IP-episode cooldown lowers that, but the README must still give this sizing guidance.
- Pre-existing, out of scope for the redesign but tracked: accept errors such as EMFILE end a listener permanently (needs backoff/retry); PROXY protocol has no source allowlist.
- `simulated: true` alerts yield simulated decisions that are not in the bouncer stream (verified), so it cannot be used when bans are wanted; opting out of CAPI sharing is a CrowdSec-side setting.
- The in-memory cooldown resets on restart: one extra alert per IP, acceptable.
- Scan state is lossy under cap eviction; acceptable for a sensor.
- A failed LAPI push holds the batch worker for max(batch interval, 1s) so the request rate no longer follows the attacker session rate; cooldown slots of failed alerts are released, and the queue (256) drops when full while the worker is held.
- `RAN_CROWDSEC_MAX_TRACKED` defaults to 20000 (was 100000 in the draft): a 1M unique-source flood peaked at 227 MB heap with 100000, above the 128 MB container limit. About 400 B per entry per structure, three structures share the cap (about 25 MB at 20000); the README recommends `GOMEMLIMIT` at about 80 percent of the container limit.

## Migration from 0.3.x
1. Add the example profiles.yaml (or equivalent) to CrowdSec and reload.
2. Remove `RAN_CROWDSEC_BAN_DURATION`, `RAN_CROWDSEC_DECISION_CACHE`, `RAN_CROWDSEC_DEDUP_WINDOW`; optionally set `RAN_BAN_ON` and `RAN_ALERT_COOLDOWN`.
3. Update Grafana panels using `stage="cached"` or `"deduplicated"`.
4. Existing decisions with origin `ran` expire normally; `GetDecisionsCount` history stays inflated for old IPs.

## Implementation notes
- Traps report through `Session.Alert(ctx, meta)`, which hands a `SessionInfo` snapshot (socket-peer IP, counters, dest port) to an `alert.Alerter`. The `Alerter` interface is `Alert(ctx, SessionInfo, meta) Class`, `SessionEnd(SessionInfo) bool`, `Close()`. A `Sensor` (classifier, scan tracker, probe log) wraps a `Sink` (the CrowdSec client, or none when CrowdSec is off); the cooldown, class filter and pipeline metrics live in the CrowdSec sink.
- `SessionEnd` reports escalations that happened after the last `Alert` call, probes, and scans whose triggering session sent nothing, so a session is submitted again only when its final class outranks the class already reported.
- Probe log: for TCP sessions with a sensor, the `session started` line is held back and written right before the first auth/command/payload line (or at the end when aggregation is off); probe sessions log nothing per session. `RAN_PROBE_SUMMARY_WINDOW=0s` turns aggregation off. `payload_bytes` counts the string attribute bytes passed to `LogPayload` (at least 1 per payload event).
- Pipeline stages `invalid` and `closed` from `security-hotfix` stay.

## Open Questions (resolved)
- `RAN_CROWDSEC_SIMULATED`: not added, documented only.
- The summary window is configurable via `RAN_PROBE_SUMMARY_WINDOW` (default 60s).
- `dynamic-ban-escalation` handling stays a task for archive time (3.4).
- Scan is always its own alert, even when the triggering session was only a probe.
