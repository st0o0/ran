## Context

CrowdSec LAPI evaluates `profiles.yaml` only for alerts without embedded decisions. ran embeds one, so profile `duration_expr` and `GetDecisionsCount` never run, and the embedded 4h decision always wins. Re-pushes after the decision-cache or dedup window add one decision row per push; `GetDecisionsCount` counts all rows for the IP, including expired ones, so counts reflect traffic volume rather than distinct episodes. Logging is one line per session, dominated by VNC probes at scale.

Variante Y (decided by the operator): ran is a sensor. It classifies, rate-limits per episode, and pushes alerts without decisions and with `remediation: true`; profiles decide.

## Goals / Non-Goals

**Goals:** profiles actually run; escalation counts episodes; classification usable in profile filters; far less log volume; minimal beginner setup (copy one profiles.yaml).

**Non-Goals:** the per-trap fixes (follow-up change), `security-hotfix` items, ran-side bans.

## Decisions

### Alert shape
`decisions: []`, `remediation: true`, `simulated: false`, scenario `custom/ran-<proto>-trap`, `Source{Scope:"Ip", Value:ip}`. One event with meta: `class`, `protocol`, `dest_port`, `auth_attempts`, `commands`, `payload_bytes`, plus existing trap meta. Profiles select with `Alert.Events[0].GetMeta("class") == "attack"`.

### Classification
- attack: auth attempts > 0, or commands > 0, or payload bytes > 0.
- probe: connect and banner only.
- scan: >= 3 distinct TCP trap protocols from one IP within 10 minutes. UDP never counts (spoofable, and already excluded from alerting by `security-hotfix`).

`Session` already counts authAttempts, commands and payloads; payload bytes is a new counter. Until the per-trap follow-up lands, traps that call `Alert` without counters (redis commands, memcached, VNC) classify as `probe` unless they log an auth attempt, command or payload; this is accepted for 0.4.0 and called out in the README.

### Scenario naming
Keep `custom/ran-<proto>-trap` for all classes, including scan (the scan alert uses the protocol that crossed the threshold). Rejected `custom/ran-scan`: it would break existing dashboards and scenario filters; the `class` meta is enough.

### Cooldown replaces cache and dedup
`RAN_ALERT_COOLDOWN` (default 4h) keyed by IP plus class: the first qualifying session sends an alert, later ones in the window only update logs and metrics. A move to a higher class (probe to attack, attack to scan) bypasses the cooldown once. The map is capped (same cap policy as `security-hotfix`) with oldest-first eviction. Default 4h matches the base profile duration, so a continuous attacker produces about one decision row per ban period and `GetDecisionsCount` counts episodes.

### Aggregated logging
Per IP and 60s window, one summary line (sessions per protocol, class counts, totals) replaces per-session connect/disconnect lines for probe sessions. Attack sessions keep full lines (credentials and commands are the research value). Metrics are updated per session as before, so dashboards are unaffected.

### Metrics
`ran_connections_total`, `ran_credentials_captured_total`, `ran_active_sessions`, `ran_session_duration_seconds` and `ran_crowdsec_alerts_dropped_total` keep names and labels. `ran_crowdsec_pipeline_total` keeps `received`, `queued`, `sent`, `failed`, `dropped`; `cached` and `deduplicated` are replaced by `cooldown` and `filtered` (class not in `RAN_BAN_ON`). Dashboards querying the old stages must be updated. No `class` label is added to existing metrics (cardinality, compatibility).

### Config
Removed: `RAN_CROWDSEC_BAN_DURATION`, `RAN_CROWDSEC_DECISION_CACHE`, `RAN_CROWDSEC_DEDUP_WINDOW`. Added: `RAN_BAN_ON`, `RAN_ALERT_COOLDOWN`. `RAN_CROWDSEC_BATCH_INTERVAL` and `RAN_CROWDSEC_BATCH_SIZE` stay. Removed variables found in the environment log a one-time warning instead of failing startup.

### Example profiles (README)
attack: base 4h, `duration_expr: Sprintf('%dh', Min(4 * (3 ^ GetDecisionsCount(Alert.GetValue())), 168))`. scan: longer base (24h) with the same escalation, cap 720h. probe: no profile, hence no ban. Profiles use `on_success: break`, scan profile first.

## CrowdSec behaviors to document
- Alerts without decisions are still forwarded to CAPI (custom scenarios) unless `simulated: true`. Operators who do not want to share must disable CAPI sharing on the CrowdSec side.
- Allowlists apply to alerts without decisions, so allowlisted IPs are never banned.
- Machine credentials stay required.
- `GetDecisionsCount` needs `db_config.flush.max_age` longer than the escalation horizon.

## Risks / Trade-offs
- No profile means no ban: a silent regression for 0.3.x users. Mitigation: migration notes and a startup log line stating that ran does not ban by itself.
- `db_config.flush.max_items` can delete old decision rows and reset counts earlier than expected; document and recommend a generous value.
- `simulated: true` alerts yield simulated decisions that bouncers ignore by default, so it cannot be used when bans are wanted; opting out of CAPI sharing is a CrowdSec-side setting.
- The in-memory cooldown resets on restart: one extra alert per IP, acceptable.
- Scan state is lossy under cap eviction; acceptable for a sensor.

## Migration from 0.3.x
1. Add the example profiles.yaml (or equivalent) to CrowdSec and reload.
2. Remove `RAN_CROWDSEC_BAN_DURATION`, `RAN_CROWDSEC_DECISION_CACHE`, `RAN_CROWDSEC_DEDUP_WINDOW`; optionally set `RAN_BAN_ON` and `RAN_ALERT_COOLDOWN`.
3. Update Grafana panels using `stage="cached"` or `"deduplicated"`.
4. Existing decisions with origin `ran` expire normally; `GetDecisionsCount` history stays inflated for old IPs.

## Open Questions
- Add `RAN_CROWDSEC_SIMULATED` so operators can opt out of CAPI sharing, or document only?
- Make the 60s summary window configurable?
- Should `dynamic-ban-escalation` be archived first so its `ban-escalation-guide` spec is not left stale?
- Should scan always be its own alert even when the triggering session was only a probe? (Current design: yes.)
