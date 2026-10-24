## ADDED Requirements

### Requirement: MCP handshake and tool listing
The `mcp` trap SHALL answer JSON-RPC 2.0 `initialize`, `ping`, `notifications/initialized`, `tools/list`, `resources/list` and `prompts/list` over HTTP (`POST /mcp` and `POST /`) with static responses. The tool list SHALL contain only inert decoy tools (`read_file`, `list_directory`, `run_command`, `get_secrets`). The resource and prompt lists SHALL be empty. The `protocolVersion` of `initialize` SHALL be echoed only when it is one of a fixed allow-list, else a fixed version is answered; client strings SHALL never be reflected. Requests SHALL be limited to 16 KiB.

#### Scenario: Tool listing
- **WHEN** a client posts `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
- **THEN** a result with the decoy tools is returned and the session stays a `probe`

#### Scenario: Notification
- **WHEN** a client posts `notifications/initialized` without an id
- **THEN** the answer is `202` without a body and the session stays a `probe`

#### Scenario: Malformed JSON
- **WHEN** the body is not valid JSON
- **THEN** a JSON-RPC error `-32700` is returned and nothing panics

#### Scenario: Invalid request and unknown method
- **WHEN** the body is valid JSON but not a JSON-RPC 2.0 request
- **THEN** the error `-32600` is returned
- **WHEN** the method is unknown and the message has an id
- **THEN** the error `-32601` is returned

#### Scenario: Batch
- **WHEN** a client posts an array of at most 16 messages
- **THEN** an array with one answer per message that has an id is returned (`202` without a body when none has)
- **WHEN** the array is empty or has more than 16 elements
- **THEN** a single error `-32600` is returned

#### Scenario: Oversized body
- **WHEN** the body is larger than 16 KiB
- **THEN** the answer is `413` with an error `-32600`, nothing of the body is logged and the session stays a `probe`

#### Scenario: Request id
- **WHEN** the id is an integer of at most 15 digits or a string of at most 64 characters from `A-Za-z0-9._:-`
- **THEN** it is echoed
- **WHEN** it is anything else
- **THEN** `null` is answered

### Requirement: Other routes
`GET /sse` SHALL return a finished event stream. `GET`, `DELETE` and every other method on `/mcp` and `/` SHALL answer `405` with `Allow: POST`. Other paths SHALL answer `404`. Exploit paths and JNDI strings SHALL be recorded as commands like in the `http` trap.

#### Scenario: SSE
- **WHEN** a client requests `GET /sse`
- **THEN** one `endpoint` event is sent and the response ends

### Requirement: Tool calls are attacks
A `tools/call` request SHALL be recorded as a command with the tool name (64 bytes) and a bounded argument summary (at most 8 keys in sorted order, 128 bytes per string value, objects and arrays not descended into, values of secret-looking keys, matched case-insensitively by substring, replaced by `***`; credential-looking text in the command string such as `Authorization: Bearer x`, `Cookie: x`, `KEY=value` with a secret-like name, `--token x` or URL userinfo replaced by `***`, always in the alert meta and in the log unless `RAN_LOG_PASSWORDS=on`), answered with an `isError` result that reflects no client text, and SHALL classify the session as `attack`. Nothing SHALL be executed. The alert meta SHALL contain `command` and `tool` besides the common HTTP keys.

#### Scenario: Command tool
- **WHEN** a client calls `run_command` with `{"command":"cat /etc/passwd"}`
- **THEN** a command is logged with the tool name and the bounded argument, an alert is raised and an error result is returned

#### Scenario: Injection text in arguments
- **WHEN** an argument contains control characters or a prompt-injection string
- **THEN** control and format characters are replaced, the value is cut to the bound and it is never interpreted or reflected

#### Scenario: Deep nesting
- **WHEN** the arguments are nested thousands of levels deep
- **THEN** the request is answered without a panic and the nested value is summarized as `<array>` or `<object>`

### Requirement: Credential headers
An `Authorization` or `X-API-Key` header SHALL be recorded as an auth attempt with only the first 8 hex characters of its SHA-256 (`token_hash`) and SHALL classify the session as `attack`. The value SHALL never be stored. `Mcp-Session-Id` SHALL be neither logged nor used.

#### Scenario: Bearer token
- **WHEN** a request carries `Authorization: Bearer <token>`
- **THEN** the log and the alert meta hold the hash prefix and never the token

### Requirement: Alert identity
The alert IP SHALL be the socket peer (or the PROXY protocol address when enabled). Header values SHALL only be logged as claimed values. Sources on the ignore list SHALL not raise alerts.

#### Scenario: Forwarded header
- **WHEN** a request carries `X-Forwarded-For`
- **THEN** it is logged as `claimed_client_ip` and does not change the alert IP
