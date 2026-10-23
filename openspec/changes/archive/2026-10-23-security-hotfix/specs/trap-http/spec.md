## MODIFIED Requirements

### Requirement: CrowdSec alert on credential capture
The HTTP trap SHALL call `alerter.Alert()` with the socket peer IP and protocol `http` on every credential POST. The `X-Real-IP` and `X-Forwarded-For` headers SHALL NOT influence the alert IP; a syntactically valid header IP SHALL be logged in a separate `claimed_client_ip` field.

#### Scenario: HTTP credential POST triggers alert
- **WHEN** an attacker POSTs credentials to a login page
- **THEN** `alerter.Alert(ctx, <peer IP>, "http", ...)` is called

#### Scenario: Spoofed forwarding header
- **WHEN** a POST from peer `198.51.100.7` carries `X-Forwarded-For: 203.0.113.9`
- **THEN** the alert IP is `198.51.100.7` and the log contains `claimed_client_ip=203.0.113.9`

#### Scenario: Garbage header
- **WHEN** `X-Real-IP` is `not-an-ip`
- **THEN** the alert IP is the peer IP and no `claimed_client_ip` field is logged

## ADDED Requirements

### Requirement: Request body limit
The HTTP trap SHALL wrap the request body with `http.MaxBytesReader` (16 KiB) before parsing forms and SHALL set `MaxHeaderBytes` to 16 KiB.

#### Scenario: Oversized POST
- **WHEN** a client POSTs a body larger than 16 KiB
- **THEN** form parsing fails, credentials are empty and memory use stays bounded
