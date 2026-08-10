## Purpose

VNC honeypot trap that simulates a VNC server to capture unauthorized authentication attempts via the RFB protocol.

## Requirements

### Requirement: VNC authentication capture
The VNC trap SHALL listen on TCP, send an RFB protocol version, negotiate VNC Authentication (security type 2), send a 16-byte challenge, capture the DES-encrypted response, log it, and respond with SecurityResult failure.

#### Scenario: VNC auth challenge-response
- **WHEN** a client completes the RFB version exchange and responds to the VNC auth challenge
- **THEN** the trap SHALL log the auth attempt with the encrypted response (hex-encoded), alert CrowdSec, and send SecurityResult=1 (failed) with "Authentication failed"

#### Scenario: RFB version negotiation
- **WHEN** a client connects
- **THEN** the trap SHALL send `RFB 003.008\n`, read the client version, and offer security type 2 (VNC Authentication)
