## 1. Implementation

- [x] 1.1 Add payload byte counter to `Session` and expose counters to the alerter
- [x] 1.2 Implement classifier (probe/attack) and capped scan tracker (TCP only, 3 protocols, 10 min)
- [x] 1.3 Remove embedded decision, set `remediation: true`, add class/protocol/dest_port/counter meta in `crowdsec.go`
- [x] 1.4 Replace decision cache and dedup with per-IP+class cooldown (capped map, class-escalation bypass)
- [x] 1.5 Add `RAN_BAN_ON` and `RAN_ALERT_COOLDOWN` to config; drop `RAN_CROWDSEC_BAN_DURATION`, cache and dedup vars with one-time warning
- [x] 1.6 Update pipeline metric stages (`filtered`, `cooldown`); keep other `ran_*` names and labels
- [x] 1.7 Implement aggregated probe logging per IP and window
- [x] 1.8 Delete `decision_cache.go` and `dedup.go` and their tests; wire `cmd/ran`

- [x] 1.9 Set both `Source.IP` and `Source.Value`, plus `capacity: 0`, `leakspeed: "0"`, `simulated: false` in the alert payload
- [x] 1.10 Follow-up: add backoff/retry to the accept loop so errors such as EMFILE do not end the listener permanently
- [ ] 1.11 Follow-up: add a source allowlist for PROXY protocol
- [x] 1.12 Bound trap meta (256 byte values at rune boundary, 64 byte keys, control chars to space, max 32 keys, sensor keys survive) and flush batches early above 512 KiB
- [x] 1.13 Release cooldown slots of a failed batch (stage `released`)
- [x] 1.14 Run the sensor maintenance ticker (scan cleanup) even with `RAN_PROBE_SUMMARY_WINDOW=0`
- [x] 1.15 Close the probe log on `Sensor.Close` (straggler sessions log per session), unmap probe log keys, ignore non-TCP in `Sensor.Alert`; traps stop before the sensor closes (checked in `cmd/ran/run.go`)
- [x] 1.16 Trap classification: Elasticsearch plain GETs and Minecraft server-list pings stay probes (`Session.Log`); redis, memcached, imap and irc alert on the first command with the command name only
- [x] 1.17 Document modbus and ADB single-request attack classification as a known follow-up (AGENTS.md)
- [x] 1.18 Pace failed pushes: after a failed flush the worker holds for max(batch interval, 1s) (interruptible by Close), failure warnings are rate limited (one per 10s with a suppressed counter), re-login happens at most once per paced interval; released cooldown slots stay, a full queue still drops
- [x] 1.19 Batch size uses the real marshaled alert length (each alert is encoded once and reused for the POST body)
- [x] 1.20 Meta sanitizing skips empty keys and replaces U+2028, U+2029 and Unicode format characters (Cf) with a space
- [x] 1.21 Elasticsearch HEAD is classified like GET (probe)
- [x] 1.22 `Session.LogCommand` redacts credential arguments (AUTHENTICATE, LOGIN, PASS, OPER, AUTH, AUTH2, IDENTIFY, requirepass, masterauth) according to `RAN_LOG_PASSWORDS`; HTTP proxy URL userinfo is stripped from log and alert
- [x] 1.23 Default `RAN_CROWDSEC_MAX_TRACKED` lowered to 20000 (memory sizing and `GOMEMLIMIT` note in the README)
- [x] 1.24 UDP read loops are tracked in the trap wait group and exit on a closed socket; `panicLog` is an atomic pointer (test race fix)
- [x] 1.25 Lint: De Morgan rewrite in `sensor_session_test.go` (QF1001)

## 2. Tests

- [x] 2.1 Classifier and scan tracker unit tests (UDP ignored, window expiry, cap eviction)
- [x] 2.2 Alerter tests: no decisions, remediation true, meta keys, filtered, cooldown, escalation bypass
- [x] 2.3 Config tests for new and removed variables
- [x] 2.4 Metrics tests for new stages and unchanged names
- [x] 2.5 Log aggregation tests and integration test against a fake LAPI
- [x] 2.6 Tests for meta bounds, batch byte cap, released cooldown, cleanup with window 0, closed probe log, mapped IP keys, UDP guard, scan boundary and mapped/plain pair, config (`abc`, empty `RAN_BAN_ON`), metrics stages `invalid`, `closed`, `released`
- [x] 2.7 Trap classification tests (probe versus attack) for elasticsearch, minecraft, redis, memcached, imap, irc
- [x] 2.8 Tests for paced failed pushes (burst of 100 sessions, hold interrupted by Close, drop when full, no goroutine leak, paced re-login, warning suppression), escaped batch size, meta format characters and empty keys, ES HEAD, command redaction in off/mask/on

## 3. Docs

- [x] 3.1 Rewrite README CrowdSec section: sensor model, config table, pipeline diagram
- [x] 3.2 Add profiles.yaml example keyed by class and CrowdSec behavior notes (CAPI, simulated, allowlists, flush settings)
- [x] 3.2a README example uses `Sprintf('%.0fh', min(168.0, 3 ^ GetDecisionsCount(Alert.GetValue())))` and event-form `Alert.Events[0].GetMeta("class")`; warn about `Min` and `%dh`
- [x] 3.2b Document `db_config.flush.max_items`/`max_age` sizing for the 168h horizon (alert history bounds escalation memory)
- [x] 3.3 Add 0.3.x to 0.4.0 migration notes
- [x] 3.5 Fix example profiles to the `filters:` list form accepted by CrowdSec v1.8.1 and update README, specs and design
- [x] 3.4 Sync delta specs to main specs; resolve `dynamic-ban-escalation` before archive (superseded `ban-escalation-guide` removed)

## 4. Release

- [ ] 4.1 Confirm `security-hotfix` (0.3.8) is released
- [ ] 4.2 Update Grafana dashboards using `cached`/`deduplicated` stages
- [ ] 4.3 Cut 0.4.0 via release-please with breaking-change notes

## 5. Round 3

- [x] 5.1 Lifecycle: no start sleep, metrics port bound before traps start, metrics server death or all traps failing cancels everything, no `os.Exit` in goroutines, traps and metrics server stop in parallel within 4s of a shared 9s shutdown budget (see 6.1), metrics server has header/read/write/idle timeouts and `Shutdown`
- [x] 5.2 Typed `alert.Transport`; consumer-side `trap.Reporter` (Alert, SessionEnd) instead of the full alerter; `Close` stays with the owner
- [x] 5.3 `ran healthcheck` exits 1 on invalid config and dials 127.0.0.1; new `ran check-config` (exit 0 or 1); remedy-style config errors, validated `RAN_*_ADDR`, sorted trap names
- [x] 5.4 Metrics: session duration buckets 0.1 to 120 s, `ran_crowdsec_push_duration_seconds`, `ran_crowdsec_push_errors_total`, `ran_crowdsec_queue_length`, `ran_tracked_entries{map}`, `ran_tracked_evictions_total{map}`, `ran_probe_summary_suppressed_sessions_total`, `ran_sessions_rejected_total{protocol}`; tests and README table
- [x] 5.5 Dockerfile: non-root `65532`, CA bundle, `/data` volume owned by 65532, `-trimpath`; builder image kept as the existing digest-pinned `golang:1.27-alpine` (no verified 1.26 digest available offline)
- [x] 5.6 README: threat model, GOMEMLIMIT and sizing, `read_only`/`cap_drop` compose settings, auth/PROXY/per-trap variables
- [x] 5.7 CrowdSec client: request contexts everywhere, flush context detached with 5s timeout, bounded and drained response bodies, single login path, `doPost` returns errors and the caller logs once
- [x] 5.8 Trap hygiene: `isTimeout`/`setOutcome` replace the copied timeout blocks, `Session.Cred` for identical credential blocks, `ResolveSessionTimeout` in every TCP trap, explicit `too_long` outcome, HTTP sessions keyed per connection instead of `RemoteAddr`
- [x] 5.9 Contract tests: trap key sets, README versus config variables, `MaxTracked` default 20000
- [x] 5.10 Reduced detectability: MySQL banner 8.0.36, Elasticsearch node name `node-1`, SMTP host `mx.localdomain`; dead `capHigh` removed
- [x] 5.11 `gofmt` on config files; De Morgan lint fix in `redactCommand`
- [x] 5.12 CI: `.github/workflows/extra-ci.yml` (386 build/vet, govulncheck, openspec validate, 20s fuzz smoke); SECURITY.md hardening note
- [x] 5.13 Nine new fuzz targets in `internal/trap/fuzz_test.go`; fixed negative offset panic in `parseDNSName`
- [x] 5.14 Follow-up done in change `trap-lifecycle`: shutdown stall handling and the shared `tcpServer` skeleton

## 6. Round 5

- [x] 6.1 Shared shutdown deadline (9s, below Docker 10s): traps and metrics server 4s, sink Close gets the remainder via `CloseContext`; CrowdSec drain capped at the 5s flush timeout and the shared deadline; README, design and spec updated
- [x] 6.2 `/data` ownership on upgrade: SSH host key read errors other than not-exist, corrupt keys and write failures log a warning (with the `chown -R 65532:65532` remedy); README upgrade note and proposal mark it breaking
- [x] 6.3 Secrets in free-form commands: Elasticsearch command is method and path only, proxy CONNECT/target drop userinfo, query and fragment, `boundMeta` drops `password`, `pass`, `passwd`, `secret`, `token`, `authorization` case-insensitively, Redis AUTH records the username under `username`, `redactCommand` covers ACL SETUSER, CONFIG SET requirepass/masterauth/masteruser; tests
- [x] 6.4 CrowdSec Close during a failure hold makes one final flush attempt (2s) for the first pending batch; test
- [x] 6.5 `tcpServer.Start` after `Stop` closes `Ready`; test
- [x] 6.6 `run` returns an error (exit code 1) when all traps exit cleanly while the context is live; test
- [x] 6.7 `LogRejected` warning rate limited per protocol (once per 10s with a suppressed count) for TCP and UDP, metric unchanged; test
- [x] 6.8 Proposal mentions the user-visible fingerprint changes (MySQL 8.0.36, SMTP `mx.localdomain`, Elasticsearch `node-1`)
- [x] 6.9 Race fixes: HTTP, Elasticsearch and HTTP proxy `Start` read the config before `Ready` closes (tests may then write the address); UDP `Start` after `Stop` also closes `Ready`
- [x] 6.10 `run` logs "trap failed to start" in the start goroutine and waits briefly for stopped traps, so the line is never lost to a shutdown race
- [x] 6.11 Lint fixes in lifecycle/startup/elasticsearch/httpproxy tests; unused `startTrap` removed
- [x] 6.12 `go.mod` raised to 1.26.10 (newest `golang:1.26.x` image) for stdlib vulnerability fixes; AGENTS.md updated
