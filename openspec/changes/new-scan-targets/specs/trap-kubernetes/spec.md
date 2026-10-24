## ADDED Requirements

### Requirement: Kubernetes API and kubelet stub
The `kubernetes` trap SHALL answer `/version`, `/healthz` and `/api` with plausible static responses and return `401` or `403` for other paths. Kubelet paths `/pods` and `/runningpods` SHALL return an authorization error.

#### Scenario: Version probe
- **WHEN** a client requests `GET /version`
- **THEN** a JSON version document is returned and the session stays a `probe`

### Requirement: Kubelet execution attempts
A request to `/run`, `/exec` or `/attach` paths of the kubelet API SHALL be recorded as a command (path and bounded command) and refused.

#### Scenario: Remote exec attempt
- **WHEN** a client posts to `/run/default/pod/container` with `cmd=id`
- **THEN** a command is logged, an alert is raised, the session is `attack` and nothing is executed

### Requirement: Token handling
A bearer token SHALL be recorded as an auth attempt with only a short hash prefix of the token. The token itself SHALL NOT be logged or sent to CrowdSec.

#### Scenario: Bearer token
- **WHEN** a client sends `Authorization: Bearer abc`
- **THEN** an auth attempt with a hash prefix is logged and the token value never appears in logs or alert meta
