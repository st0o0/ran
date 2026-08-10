## Purpose

MQTT honeypot trap that simulates an MQTT broker to capture client credentials and connection attempts.

## Requirements

### Requirement: MQTT CONNECT credential capture
The MQTT trap SHALL listen on TCP, accept MQTT CONNECT packets, extract username/password and client ID, log them, and respond with CONNACK indicating authentication failure (return code 4 for MQTT 3.x, reason code 0x86 for MQTT 5).

#### Scenario: MQTT 3.1.1 credential capture
- **WHEN** a client sends a CONNECT packet with protocol level 4, username="device1", password="secret"
- **THEN** the trap SHALL log auth_attempt with those credentials and client_id, alert CrowdSec, and respond with CONNACK return_code=4 (bad username or password)

#### Scenario: MQTT 5 credential capture
- **WHEN** a client sends a CONNECT packet with protocol version 5 and credentials
- **THEN** the trap SHALL log the credentials and respond with CONNACK reason_code=0x86

#### Scenario: CONNECT without credentials
- **WHEN** a client sends a CONNECT without username/password flags
- **THEN** the trap SHALL log the client_id and respond with CONNACK return_code=5 (not authorized)
