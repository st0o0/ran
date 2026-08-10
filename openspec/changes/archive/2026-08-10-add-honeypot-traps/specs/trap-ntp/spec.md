## ADDED Requirements

### Requirement: NTP request logging
The NTP trap SHALL listen on UDP, parse NTP packets, log the mode and version, and respond with a Kiss-of-Death (KoD) packet.

#### Scenario: Client mode request
- **WHEN** an NTP packet with mode=3 (client) arrives
- **THEN** the trap SHALL log a payload event with mode="client", version, and source IP, alert CrowdSec, and respond with a KoD packet (stratum=0, kiss code "DENY")

#### Scenario: Monlist request (amplification probe)
- **WHEN** an NTP private mode packet (mode=7) with request code 42 (MON_GETLIST) arrives
- **THEN** the trap SHALL log it as an amplification attempt and not respond (drop the packet)

#### Scenario: Malformed NTP packet
- **WHEN** a packet is shorter than 48 bytes (minimum NTP packet)
- **THEN** the trap SHALL silently drop the packet
