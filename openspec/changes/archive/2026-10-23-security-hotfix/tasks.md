## 1. HTTP trap

- [x] 1.1 Use `sess.SourceIP` as alert IP; log validated header IP as `claimed_client_ip`
- [x] 1.2 Add `MaxBytesReader` (16 KiB) before `ParseForm` and set `MaxHeaderBytes`
- [x] 1.3 Unit tests: spoofed XFF, garbage header, oversized body

## 2. Alerter

- [x] 2.1 Validate and unmap IP in `Alert()`; add `invalid` pipeline stage
- [x] 2.2 Cap dedup map and decision cache (`RAN_CROWDSEC_MAX_TRACKED`)
- [x] 2.3 Record dedup slot only after successful enqueue
- [x] 2.4 Strip `password` from event meta
- [x] 2.5 Unit tests: invalid/private/mapped IPs, caps, dropped-alert retry, no password meta
- [x] 2.6 Replace the IP check with an explicit non-global prefix denylist (CGNAT, documentation, 6to4, NAT64 and others) and table tests for every prefix
- [x] 2.7 Make dedup and decision cache FIFO with O(1) insert, expiry and eviction; Release compares the slot; Close is idempotent and Alert-safe
- [x] 2.8 Tests: 200000-key flood is fast, concurrent Allow/Release/Alert, stale Release, Close guard
- [x] 2.9 `Alert()` after `Close()` increments pipeline stage `closed`; `MarkBanned` keeps the later expiry; document the eviction trade-off in dedup.go and decision_cache.go
- [x] 2.10 Extend the IP denylist with 64:ff9b:1::/48, 2001::/23, 3fff::/20 and 5f00::/16 (table tests, design D3)

## 3. Bounded parsing

- [x] 3.1 Redis: cap args, bulk length, line length
- [x] 3.2 LDAP: cap BER length
- [x] 3.3 Add `readLineLimited` and use in telnet, redis inline, PROXY v1
- [x] 3.4 Fuzz/limit tests for redis and ldap (huge counts, huge lengths, truncated input)
- [x] 3.5 Parse PROXY headers off the accept path under a 3s deadline; validate v1 address and port; Close never hangs; tests for silent peer and Close
- [x] 3.6 Fix negative BER INTEGER encoding (panic on 8 byte message IDs); regression test and fuzz seed
- [x] 3.7 Guard 32-bit int overflow in berReadLength, berReadTLV and ntlmsspReadField via fitsInt; unit tests
- [x] 3.8 Require the PROXY header with `RAN_PROXY_PROTOCOL`: close and count (`ran_proxy_protocol_dropped_total`) connections with no valid v1/v2 header, remove the plain-connection fallback, update tests
- [x] 3.9 Bound pending PROXY handshakes with a semaphore (1024) and time out the handoff to `Accept`; flood and stalled-consumer tests
- [x] 3.10 `parseV2`: require version 2 and cap the address block at 536 bytes; table tests
- [x] 3.11 `berReadInteger` rejects length 0 and above 8; test

## 4. Panic isolation

- [x] 4.1 Add `safely` helper and `ran_panics_recovered_total`
- [x] 4.2 Wrap handlers, accept goroutines, UDP packet goroutine
- [x] 4.3 Test: panicking handler does not stop the trap or leak limiter slots
- [x] 4.4 Rate limit panic logs per protocol (stack for the first 5, then 1/s sampled) while always counting; fake-clock test
- [x] 4.5 Wrap HTTP handlers with `recoverHandler` so handler panics are counted and logged once
- [x] 4.6 Back off (10ms doubling to 1s) after a recovered `Accept` panic; test with a panicking listener

## 5. UDP

- [x] 5.1 Keep UDP handlers from alerting (dns, ntp, snmp, sip; see 5.4)
- [x] 5.2 Per-source and global token-bucket rate limit with capped state
- [x] 5.3 Tests: no alert on UDP, flood is bounded
- [x] 5.4 Remove the alerter from the dns, ntp, snmp and sip handlers and constructors; smoke test per protocol
- [x] 5.5 Deterministic flood test with the injected clock; limiter test for 10000 packets in one second; source cap falls back to the global bucket
- [x] 5.6 Count rate-limited UDP packets in `ran_udp_rate_limited_total{protocol}`; reject `RAN_UDP_RATE_BURST` below `RAN_UDP_RATE_PER_SOURCE` at startup (test)

## 6. Password logging

- [x] 6.1 Add `RAN_LOG_PASSWORDS` config (`off` default, `mask`, `on`) with validation
- [x] 6.2 Apply in `Session.LogAuthAttempt` path
- [x] 6.3 Config and logging tests

## 7. Docs and specs

- [x] 7.1 README and config docs: new env vars, behavior changes, upgrade notes
- [x] 7.4 Document the deviations (ListenMultiTCP args, malformed PROXY header, BER length encodings), per-trap UDP limiter and source cap, IP denylist, PROXY deadline and the LAPI traffic note in README, design and delta specs
- [x] 7.5 Document required PROXY header and trusted-proxy-only warning, new metrics, `closed` stage, burst validation and the extended denylist in README, design, proposal (BREAKING) and delta specs
- [x] 7.6 Test log buffers written by server goroutines are mutex-guarded and the HTTP panic test waits for the handler log before asserting (clean under `-race`)
- [x] 7.2 Update `trap-dns`, `trap-ntp`, `trap-snmp`, `trap-sip` specs on sync
- [x] 7.3 Sync delta specs to main specs before archive

## 8. Release 0.3.8

- [x] 8.1 Run `go vet`, `golangci-lint`, `go test -race ./...`
- [x] 8.2 Changelog entry with BREAKING behavior notes
- [ ] 8.3 Tag and release 0.3.8 via the release workflow
- [x] 8.4 Archive change
