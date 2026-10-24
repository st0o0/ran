## ADDED Requirements

### Requirement: Kubernetes API and kubelet stub
The `kubernetes` trap SHALL answer `/version`, `/healthz` (also `/livez` and `/readyz`) and `/api` with plausible static responses and return `403` (`401` when a bearer token was presented) for other paths. Kubelet paths `/pods` and `/runningpods` SHALL return `401`. It SHALL reuse the request handling of the `http` trap (one session per connection, 16 KiB limits, `Stop(ctx)` closes live connections). The `10250` kubelet port is reachable by listing it in `RAN_KUBERNETES_ADDR`.

#### Scenario: Version probe
- **WHEN** a client requests `GET /version`
- **THEN** a JSON version document is returned and the session stays a `probe`

### Requirement: Kubelet execution attempts
A request to `/run/`, `/exec/` or `/attach/` paths of the kubelet API (any method) SHALL be recorded as a command (method, path and the `cmd` or `command` values of the query string or form body, bounded to 256 bytes) and refused.

#### Scenario: Remote exec attempt
- **WHEN** a client posts to `/run/default/pod/container` with `cmd=id`
- **THEN** a command is logged, an alert is raised, the session is `attack` and nothing is executed

### Requirement: Token handling
A bearer token SHALL be recorded as an auth attempt with only a short hash prefix (8 hex characters of the SHA-256) of the token, logged and sent as alert meta `token_hash`. The token itself SHALL NOT be logged or sent to CrowdSec, and `Authorization` and `Cookie` headers SHALL NOT be logged.

#### Scenario: Bearer token
- **WHEN** a client sends `Authorization: Bearer abc`
- **THEN** an auth attempt with a hash prefix is logged and the token value never appears in logs or alert meta

#### Scenario: Empty token
- **WHEN** the `Authorization` header is `Bearer ` without a token
- **THEN** no auth attempt is recorded
