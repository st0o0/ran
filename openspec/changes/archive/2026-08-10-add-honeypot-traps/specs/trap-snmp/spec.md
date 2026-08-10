## ADDED Requirements

### Requirement: SNMP community string capture
The SNMP trap SHALL listen on UDP, parse SNMPv1/v2c GetRequest packets (BER-encoded), extract the community string, log it, and respond with a noSuchName error.

#### Scenario: Community string capture
- **WHEN** a UDP packet contains an SNMP GetRequest with community string "public"
- **THEN** the trap SHALL log a payload event with community="public" and oid requested, alert CrowdSec, and respond with GetResponse containing error-status noSuchName

#### Scenario: SNMPv3 packet
- **WHEN** a packet appears to be SNMPv3 (version field = 3)
- **THEN** the trap SHALL log the connection attempt and respond with an SNMPv3 report (unsupportedSecurityLevel)

#### Scenario: Malformed SNMP packet
- **WHEN** a packet cannot be parsed as valid BER/ASN.1
- **THEN** the trap SHALL silently drop the packet
