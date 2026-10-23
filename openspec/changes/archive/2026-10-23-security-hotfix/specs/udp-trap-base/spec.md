## ADDED Requirements

### Requirement: UDP traps never alert
UDP traps (dns, ntp, snmp, sip) SHALL NOT raise CrowdSec alerts, because UDP source addresses are spoofable. UDP handlers SHALL have no alerter, and the UDP trap constructors SHALL NOT accept one, so a UDP handler cannot alert at all. Logging and metrics SHALL continue. This supersedes any "alert CrowdSec" wording in the `trap-dns`, `trap-ntp`, `trap-snmp` and `trap-sip` specs.

#### Scenario: DNS query
- **WHEN** a DNS query arrives over UDP
- **THEN** a payload event is logged and metrics are updated
- **AND** no alert is passed to the CrowdSec alerter

### Requirement: UDP packet rate limiting
The UDP read loop SHALL apply a per-source token bucket (default 20 pkt/s, burst 40; a configured burst below the per-source rate SHALL be rejected at startup) and a global bucket (default 2000 pkt/s) before creating a session or spawning a goroutine. Dropped packets SHALL be counted in `ran_udp_rate_limited_total{protocol}` and logged at debug only. Per-source state SHALL be size-capped at 100000 sources; once the cap is reached only the global bucket applies to untracked sources. The limiter is per UDP trap, so the global bucket is per protocol.

#### Scenario: Packet flood from one source
- **WHEN** a source sends 10000 packets in one second
- **THEN** at most the burst plus rate times elapsed seconds are handled and the rest are dropped without spawning goroutines

#### Scenario: Many spoofed sources
- **WHEN** packets arrive from more sources than the per-source map cap
- **THEN** the global bucket still bounds the handled rate and map size stays capped

#### Scenario: Dropped packets are counted
- **WHEN** the rate limiter drops packets from a flood
- **THEN** `ran_udp_rate_limited_total{protocol}` increases by the number of dropped packets

#### Scenario: Burst below per-source rate
- **WHEN** `RAN_UDP_RATE_BURST` is smaller than `RAN_UDP_RATE_PER_SOURCE`
- **THEN** configuration loading fails with an error naming `RAN_UDP_RATE_BURST`
