## ADDED Requirements

### Requirement: DNS query logging
The DNS trap SHALL listen on UDP, parse incoming DNS query packets, log the queried domain name, query type, and source IP, and respond with RCODE REFUSED.

#### Scenario: A record query
- **WHEN** a UDP packet contains a DNS query for `example.com` type A
- **THEN** the trap SHALL log a payload event with domain="example.com", qtype="A", alert CrowdSec, and respond with the same query ID and RCODE=5 (REFUSED)

#### Scenario: ANY query (amplification probe)
- **WHEN** a DNS query with qtype=ANY arrives
- **THEN** the trap SHALL log it with qtype="ANY" (indicating potential amplification attempt) and respond with REFUSED

#### Scenario: Malformed DNS packet
- **WHEN** a packet is too short to contain a valid DNS header (< 12 bytes)
- **THEN** the trap SHALL silently drop the packet
