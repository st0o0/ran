## 1. Session & Logging Foundation

- [x] 1.1 Add `Transport` and `Outcome` fields to `Session` struct, add `SetOutcome(string)` method, default outcome to `"completed"`
- [x] 1.2 Update `NewSession` to accept `transport` parameter (`"tcp"` or `"udp"`), add `"transport"` to session base logger fields
- [x] 1.3 Change `LogConnect()` from `slog.Debug` to `slog.Info`, change message to `"session started"`
- [x] 1.4 Update `LogDisconnect()`: change message to `"session ended"`, add `"outcome"` and `"transport"` fields from session
- [x] 1.5 Update `LogAuthAttempt()`: change message to `"credentials captured"`
- [x] 1.6 Update `LogCommand()`: change message to `"command received"`
- [x] 1.7 Update `LogPayload()`: change message to `"payload received"`
- [x] 1.8 Add `LogRejected(protocol, transport, destPort, sourceIP, reason string)` method on trap-level (not session), logging at Warn with `action="rejected"`, message `"connection rejected"`
- [x] 1.9 Add `LogError(errorType string, err error)` method on Session (and standalone version for non-session errors), logging at Error with `action="error"`, message `"internal error"`

## 2. UDP Trap Base Changes

- [x] 2.1 Change `PacketHandler` interface: `HandlePacket(ctx context.Context, sess *Session, data []byte, respond func([]byte))`
- [x] 2.2 Update `UDPTrap.readLoop`: call `sess.LogDisconnect()` in the goroutine defer chain after `HandlePacket` returns
- [x] 2.3 Update `UDPTrap.readLoop`: pass `sess` to `HandlePacket` instead of `src`, `destPort`
- [x] 2.4 Update `UDPTrap.readLoop`: pass `"udp"` as transport to `NewSession`
- [x] 2.5 Update rejection logging in `readLoop` to use `LogRejected` with protocol, transport, dest_port

## 3. UDP Handler Migration

- [x] 3.1 Update `dnsHandler.HandlePacket`: use `sess` parameter, remove local session creation, log parse errors with `sess.LogError("parse_failed", ...)`
- [x] 3.2 Update `ntpHandler.HandlePacket`: use `sess` parameter, remove local session creation, log parse errors
- [x] 3.3 Update `snmpHandler.HandlePacket`: use `sess` parameter, remove local session creation, log parse errors
- [x] 3.4 Update `sipHandler.HandlePacket`: use `sess` parameter, remove local session creation, replace `LogPayload("auth_attempt", ...)` with `LogAuthAttempt(...)`, log parse errors

## 4. TCP Trap Updates

- [x] 4.1 Update all TCP trap `NewSession` calls to pass `"tcp"` as transport (ssh, http, telnet, ftp, mysql, rdp, vnc, mqtt, modbus, ldap, smb, socks5, postgres, mssql, oracle, redis, memcached, pop3, imap, irc, smtp, elasticsearch, httpproxy, adb, minecraft)
- [x] 4.2 Update all TCP trap rejection logging to use `LogRejected`
- [x] 4.3 Update TCP trap accept-error logging: change from `slog.Debug("accept error")` to `LogError("accept_failed", err)` with `action="error"`
- [x] 4.4 Add outcome detection in TCP handlers: detect `net.Error.Timeout()` and call `sess.SetOutcome("timeout")`, detect other errors and call `sess.SetOutcome("error")`
- [x] 4.5 Update SSH trap: log handshake errors with `sess.LogError("handshake_failed", err)` instead of silently returning

## 5. Metrics Improvements

- [x] 5.1 Register `collectors.NewGoCollector()` and `collectors.NewProcessCollector()` on the custom registry in `metrics.New()`
- [x] 5.2 Add `ran_build_info` gauge with labels `version`, `goversion` — accept these as parameters to `metrics.New()`
- [x] 5.3 Add `ran_crowdsec_alerts_dropped_total{protocol}` counter to `Metrics` struct
- [x] 5.4 Add `ran_crowdsec_pipeline_total{protocol, stage}` counter to `Metrics` struct
- [x] 5.5 Add `outcome` label to `ran_connections_total` — change from `CounterVec` with `[]string{"protocol"}` to `[]string{"protocol", "outcome"}`
- [x] 5.6 Update `RecordStart`: increment `ran_connections_total` moves to `RecordEnd` (so outcome is known)
- [x] 5.7 Update `RecordEnd`: accept `outcome string` parameter, increment `ran_connections_total{protocol, outcome}`
- [x] 5.8 Remove old `ran_crowdsec_alerts_total`, `ran_crowdsec_alerts_cached_total`, `ran_crowdsec_alerts_deduplicated_total` from metrics struct and registration
- [x] 5.9 Update `cmd/ran/main.go`: pass `version` and `runtime.Version()` to `metrics.New()`

## 6. CrowdSec Alerter Updates

- [x] 6.1 Rename all `"ip"` log fields to `"source_ip"` in `crowdsec.go`
- [x] 6.2 Replace `CrowdSecAlerts.WithLabelValues(protocol, "success")` with `CrowdSecPipeline.WithLabelValues(protocol, "sent")`
- [x] 6.3 Replace `CrowdSecAlerts.WithLabelValues(protocol, "failure")` with `CrowdSecPipeline.WithLabelValues(protocol, "failed")`
- [x] 6.4 Replace `CrowdSecCached.WithLabelValues(protocol)` with `CrowdSecPipeline.WithLabelValues(protocol, "cached")`
- [x] 6.5 Replace `CrowdSecDeduped.WithLabelValues(protocol)` with `CrowdSecPipeline.WithLabelValues(protocol, "deduplicated")`
- [x] 6.6 Add `CrowdSecPipeline.WithLabelValues(protocol, "received").Inc()` at the top of `Alert()`
- [x] 6.7 Add `CrowdSecPipeline.WithLabelValues(protocol, "queued").Inc()` on successful channel send
- [x] 6.8 Add `CrowdSecPipeline.WithLabelValues(protocol, "dropped").Inc()` and `CrowdSecDropped.WithLabelValues(protocol).Inc()` on channel-full case
- [x] 6.9 Add `stage` field to CrowdSec log events matching the pipeline stage

## 7. Verification

- [x] 7.1 Run `go build ./...` — ensure compilation succeeds
- [x] 7.2 Run `go test ./...` — ensure all tests pass
- [ ] 7.3 Run `golangci-lint run` — ensure no lint errors (not installed locally, CI will verify)
- [ ] 7.4 Verify: start ran with `RAN_LOG_FORMAT=json`, check that connect events appear at Info level
- [ ] 7.5 Verify: scrape `/metrics`, confirm `process_start_time_seconds`, `go_goroutines`, `ran_build_info` are present
- [ ] 7.6 Verify: scrape `/metrics`, confirm `ran_crowdsec_pipeline_total` is present and old `ran_crowdsec_alerts_total` is absent
- [ ] 7.7 Verify: scrape `/metrics`, confirm `ran_connections_total` has `outcome` label
