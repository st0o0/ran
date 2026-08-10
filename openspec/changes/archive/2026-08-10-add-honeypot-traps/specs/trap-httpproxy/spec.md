## ADDED Requirements

### Requirement: HTTP proxy request capture
The HTTP proxy trap SHALL listen on TCP as an HTTP server, detect CONNECT and proxied GET/POST requests, log the target URL/host, and respond with 407 Proxy Authentication Required.

#### Scenario: CONNECT tunnel request
- **WHEN** a client sends `CONNECT evil.com:443 HTTP/1.1`
- **THEN** the trap SHALL log the proxy request with target="evil.com:443", alert CrowdSec, and respond with `407 Proxy Authentication Required`

#### Scenario: Proxied GET request
- **WHEN** a client sends `GET http://example.com/path HTTP/1.1`
- **THEN** the trap SHALL log the request with target URL, and respond with `407 Proxy Authentication Required`

#### Scenario: Proxy-Authorization header capture
- **WHEN** a client includes a `Proxy-Authorization` header
- **THEN** the trap SHALL decode and log the credentials, alert CrowdSec, and still respond with 407
