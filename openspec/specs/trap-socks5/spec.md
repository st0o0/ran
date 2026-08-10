## Purpose

SOCKS5 honeypot trap that simulates a SOCKS5 proxy server to capture unauthorized proxy usage attempts and credential harvesting.

## Requirements

### Requirement: SOCKS5 auth and proxy request capture
The SOCKS5 trap SHALL listen on TCP, handle the SOCKS5 method negotiation, optionally capture username/password authentication, log the proxy connect request, and respond with connection refused.

#### Scenario: Username/password auth capture
- **WHEN** a client offers username/password auth method (0x02) and sends credentials
- **THEN** the trap SHALL log auth_attempt with the captured username and password, alert CrowdSec, and respond with auth failure (status 0x01)

#### Scenario: No auth - proxy request capture
- **WHEN** a client negotiates no auth (0x00) and sends a CONNECT request to target host:port
- **THEN** the trap SHALL log the proxy request with target address and port, alert CrowdSec, and respond with connection refused (reply 0x05)
