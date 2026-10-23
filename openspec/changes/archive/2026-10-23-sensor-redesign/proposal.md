## Why

Today ran pushes every session as a CrowdSec alert with an embedded ban decision. CrowdSec only runs profiles for alerts that carry no decisions, so the escalation profiles documented by `dynamic-ban-escalation` are dead code and the README claim that profiles override ran's decision is wrong. Every attacker gets one flat 4h ban, `GetDecisionsCount` counts one row per packet-driven re-push, and ran emits one log line per session (the VNC trap alone is about 85% of roughly 15.9M sessions per 30 days). Probes and real attacks are not distinguished at all.

This change turns ran into a sensor: it classifies, aggregates, and pushes alerts without decisions, and CrowdSec profiles decide the ban. It assumes `security-hotfix` (0.3.8) shipped first: UDP traps no longer alert, the alert IP comes only from the socket peer, IPs are validated, in-memory maps are capped. None of that is repeated here.

## What Changes

- **BREAKING** ran stops embedding a decision in alerts. Alerts are sent with `remediation: true` and an empty `decisions` list. Without a CrowdSec profile nothing is banned. Decisions created by profiles carry origin `crowdsec`, not `ran`.
- **BREAKING** `RAN_CROWDSEC_BAN_DURATION`, `RAN_CROWDSEC_DECISION_CACHE` and `RAN_CROWDSEC_DEDUP_WINDOW` are removed. The decision cache and the dedup filter are deleted.
- **BREAKING** The image runs as non-root user `65532`. An existing root-owned `/data` volume must be fixed with `chown -R 65532:65532`; until then the SSH host key cannot be read or persisted (`ran` logs a warning and generates a new key on every start).
- User-visible fingerprint changes (reduced detectability): the MySQL banner reports version `8.0.36`, the SMTP banner and EHLO host is `mx.localdomain`, the Elasticsearch node name is `node-1`.
- Shutdown shares one 9s deadline (traps and metrics server 4s, then the sink drain within the remainder, at most 5s). If all traps exit while nothing asked to stop, the process exits with code 1.
- New `RAN_BAN_ON` (default `attack,scan`): which classes produce a CrowdSec alert. `probe` stays in logs and metrics only unless listed.
- New `RAN_ALERT_COOLDOWN` (default `4h`): at most one alert per IP and class per cooldown, so `GetDecisionsCount` counts episodes, not packets.
- New classification (`probe`, `attack`, `scan`) carried as event meta `class`, plus `protocol`, `dest_port`, `auth_attempts`, `commands`, `payload_bytes`. Scenario names stay `custom/ran-<proto>-trap`; `Source.IP` is kept so Alloy geo enrichment keeps working.
- Scan detection: at least 3 distinct TCP trap protocols from one IP within about 10 minutes, in a capped in-memory map, never counting UDP.
- Log aggregation: per-IP, per-window summary lines replace one line per session for probe sessions. Per-protocol `ran_*` metrics keep names and labels.
- README: new section explaining escalation with CrowdSec profiles keyed by `class`, with an example `profiles.yaml`; the old "Ban Escalation" section is replaced.
- Document CrowdSec behaviors: decision-less alerts are still shared to CAPI unless `simulated: true`; allowlists apply; machine credentials stay required; the alert history depth (`db_config.flush`) bounds the escalation memory.

## Capabilities

### New Capabilities

- `alert-classification`: probe, attack and scan classes, scan detection, aggregated logging.
- `profile-escalation-guide`: README guidance and example profiles for the sensor model (supersedes `ban-escalation-guide` from `dynamic-ban-escalation`).

### Modified Capabilities

- `crowdsec-alerter`: no embedded decisions, `remediation: true`, class meta, cooldown instead of cache and dedup, `RAN_BAN_ON` filtering.
- `config`: remove `RAN_CROWDSEC_BAN_DURATION` (and cache/dedup vars), add `RAN_BAN_ON` and `RAN_ALERT_COOLDOWN`.
- `metrics`: pipeline stages `cached` and `deduplicated` are replaced by `cooldown` and `filtered`.

## Impact

- `internal/alert` (crowdsec.go; delete decision_cache.go and dedup.go), `internal/config`, `internal/trap` (session counters feed the classifier), `cmd/ran`, README, Grafana dashboards using `stage="cached"` or `"deduplicated"`.
- Release 0.4.0. Operators MUST add a CrowdSec profile or nothing is banned.

## Non-goals

- Per-trap classification fixes (redis commands as attack, memcached, Elasticsearch, Minecraft and VNC meta): follow-up change.
- Anything from `security-hotfix`.
- Built-in ban logic or a ran-side decision store.
- Changing `RAN_CROWDSEC_BATCH_INTERVAL` or `RAN_CROWDSEC_BATCH_SIZE` (BATCH stays as is).
- Shipping CrowdSec scenarios or parsers.
- Pre-existing gaps from the hotfix reviews, tracked as follow-up tasks: accept-loop retry after errors such as EMFILE, and a source allowlist for PROXY protocol.
