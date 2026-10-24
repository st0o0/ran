## ADDED Requirements

### Requirement: Request logging
The HTTP trap SHALL log every request with method, path without query string, `Host`, `User-Agent` and a bounded header subset. Values SHALL be cut to 256 bytes and stripped of control characters.

#### Scenario: Plain GET
- **WHEN** a client sends `GET /index.html` with `User-Agent: zgrab/0.x`
- **THEN** a `probe` log entry with method, path and user agent is emitted and the session stays a probe

#### Scenario: Oversized header value
- **WHEN** a `User-Agent` longer than 256 bytes is sent
- **THEN** the logged value is cut to 256 bytes

### Requirement: Exploit path classification
A request whose path matches the built-in exploit path list, or whose request line or header values contain a JNDI lookup string, SHALL be recorded as a command and counted as `attack`.

#### Scenario: Secrets file probe
- **WHEN** a client requests `GET /.env`
- **THEN** a command is logged with the path and the session is classified `attack`

#### Scenario: JNDI in header
- **WHEN** a request carries `X-Api-Version: ${jndi:ldap://x/a}`
- **THEN** a command is logged and the session is classified `attack`

#### Scenario: Ordinary path
- **WHEN** a client requests `GET /robots.txt`
- **THEN** the session stays a `probe` and no alert is raised

### Requirement: Basic authorization capture
A request with an HTTP Basic `Authorization` header SHALL be recorded as an auth attempt with the decoded username (a value without a colon is a bare username; invalid base64 is ignored). The password SHALL follow `RAN_LOG_PASSWORDS` and never becomes alert meta.

#### Scenario: Basic credentials
- **WHEN** a client sends `Authorization: Basic YWRtaW46aHVudGVyMg==`
- **THEN** an auth attempt for user `admin` is logged and the session is classified `attack`

### Requirement: Non-form body as payload
A `POST`, `PUT` or `PATCH` body that is not a form login SHALL be read up to the 16 KiB limit and counted as payload bytes. A form login is a `POST` with an `application/x-www-form-urlencoded` body that has a credential field, or a `POST` with an empty body; both keep the existing auth attempt behavior.

#### Scenario: JSON body
- **WHEN** a client POSTs a 300 byte JSON body to `/api/login`
- **THEN** 300 payload bytes are recorded and the session is classified `attack`
