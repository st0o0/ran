## Why

The HTTP trap only reacts to `POST` form logins. Most web scanner traffic is `GET` (`/.env`, `/actuator`, `/wp-admin`, `/cgi-bin/...`, JNDI strings in headers). Such a request logs nothing but connect and disconnect, stays a `probe`, and with the default `RAN_BAN_ON=attack,scan` never reaches CrowdSec. An IP that only sends exploit GETs to one trap is therefore never reported, and the path, `User-Agent` and `Host` are lost.

## What Changes

- Every HTTP request is logged with method, path (no query string), `Host`, `User-Agent` and a bounded subset of headers.
- A built-in list of known exploit and recon paths (secrets files, framework admin endpoints, VCS metadata, shells) classifies a matching request as a command. Matching also covers the request line and a bounded set of header values for JNDI (`${jndi:`) strings.
- All other `GET`/`HEAD` requests stay a probe, so ordinary crawling does not produce alerts. They are summarized like other probe sessions.
- Non-form `POST` bodies (JSON, XML) count as payload bytes (bounded by the existing 16 KiB limit). HTTP Basic `Authorization` is captured as credentials.
- Alert meta gains `path`, `method` and a bounded `user_agent`. No new alert scenario, class or metric label.

## Capabilities

### Modified Capabilities

- `trap-http`: request logging, exploit-path classification, Basic auth capture. Commands from the path list count as `attack` through the existing classification rule.

## Impact

- `internal/trap/http.go` (`handleLogin`), new `internal/trap/httppaths.go` with the path list, tests with a table of paths.
- README: HTTP row and classification notes. No config or metric changes.

## Non-goals

- No query string, cookie or request body storage beyond the existing limits.
- No response emulation per path (a later change may add static fixtures).
- No change to the alert identity: still the socket peer, forwarded headers stay `claimed_client_ip`.
