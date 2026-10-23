## ADDED Requirements

### Requirement: Alert IP validation
`Alert()` SHALL parse the IP with `netip.ParseAddr`, reject zoned addresses, unmap IPv4-mapped IPv6 addresses, and reject every address inside an explicit denylist of non-global prefixes: 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4, ::/128, ::1/128, ::ffff:0:0/96, 64:ff9b::/96, 64:ff9b:1::/48, 100::/64, 2001::/23, 2001:db8::/32, 2002::/16, 3fff::/20, 5f00::/16, fc00::/7, fe80::/10, ff00::/8 and ::/96. Rejected addresses SHALL be dropped before cache and dedup, counted as pipeline stage `invalid`.

#### Scenario: Non-IP string
- **WHEN** `Alert(ctx, "not-an-ip", "http", nil)` is called
- **THEN** nothing is queued and stage `invalid` is incremented

#### Scenario: Private or loopback address
- **WHEN** `Alert()` is called with `10.0.0.5`, `100.64.0.1`, `127.0.0.1`, `169.254.1.1`, `0.0.0.0`, `203.0.113.9`, `224.0.0.1`, `::1` or `2001:db8::1`
- **THEN** nothing is queued and stage `invalid` is incremented

#### Scenario: IPv4-mapped IPv6
- **WHEN** `Alert()` is called with `::ffff:8.8.8.8`
- **THEN** the alert is queued with the unmapped IPv4 form as source value

### Requirement: Bounded dedup and decision cache
The dedup filter and the local decision cache SHALL each hold at most `RAN_CROWDSEC_MAX_TRACKED` entries (default 100000). Both SHALL be FIFO structures: on overflow expired dedup entries SHALL be dropped from the front, then the oldest entry of either structure evicted, each in O(1) amortized time without scanning the whole map under the lock. The decision cache SHALL sweep expired entries only from its cleanup loop.

#### Scenario: Map at capacity
- **WHEN** more unique IPs arrive than the cap
- **THEN** map size never exceeds the cap

#### Scenario: Flood of unique keys
- **WHEN** 200000 unique keys are inserted into a full dedup map or decision cache
- **THEN** the inserts complete well under 2 seconds and the size stays at the cap

### Requirement: Dedup slot recorded only on enqueue
The dedup slot SHALL be consumed only when the alert is successfully enqueued. If the channel is full and the alert is dropped, the slot SHALL be released, and only if the stored slot is still the one the alert took. `Close()` SHALL be idempotent and `Alert()` SHALL NOT send on a closed channel, including when called concurrently with `Close()`.

#### Scenario: Dropped alert is retried
- **WHEN** an alert is dropped because the channel is full and the same IP alerts again after space is available
- **THEN** the second alert is not suppressed by dedup

### Requirement: No password in CrowdSec meta
The alerter SHALL remove the `password` key from event meta before building the LAPI payload.

#### Scenario: Credential alert
- **WHEN** a trap calls `Alert()` with meta containing `username` and `password`
- **THEN** the LAPI event meta contains `username` and no `password`

### Requirement: Alerts after Close are counted
`Alert()` called after `Close()` SHALL NOT queue the alert and SHALL increment the pipeline stage `closed` (and log at debug) instead of returning silently.

#### Scenario: Alert after Close
- **WHEN** `Alert()` is called with a valid public IP after `Close()`
- **THEN** nothing is queued and stage `closed` is incremented

### Requirement: Decision cache keeps the longest ban
`MarkBanned` on an IP that is already cached SHALL keep the later of the existing and the new expiry, so a shorter ban never shortens a longer or permanent one.

#### Scenario: Shorter re-mark
- **WHEN** an IP is marked banned for 4 hours and then marked again for 1 minute
- **THEN** the IP stays cached as banned for the 4 hour window

### Requirement: Eviction trade-off is documented
The dedup filter and decision cache SHALL document in code that a flood of unique sources can evict an entry still inside its window, so a repeat alert may pass, and that the LAPI stays authoritative.

#### Scenario: Flood of unique sources
- **WHEN** more unique sources arrive than the tracked-entry cap
- **THEN** the oldest entry is evicted even if it is still inside its window, a repeat alert for it may pass, and the comments in dedup.go and decision_cache.go state this trade-off
