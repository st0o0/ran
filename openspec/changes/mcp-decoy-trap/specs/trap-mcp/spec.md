## ADDED Requirements

### Requirement: MCP handshake and tool listing
The `mcp` trap SHALL answer JSON-RPC 2.0 `initialize`, `ping` and `tools/list` over HTTP with static responses. The tool list SHALL contain only inert decoy tools. Requests SHALL be limited to 16 KiB.

#### Scenario: Tool listing
- **WHEN** a client posts `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
- **THEN** a result with the decoy tools is returned and the session stays a `probe`

#### Scenario: Malformed JSON
- **WHEN** the body is not valid JSON-RPC
- **THEN** a JSON-RPC error `-32700` is returned and nothing panics

### Requirement: Tool calls are attacks
A `tools/call` request SHALL be recorded as a command with the tool name and a bounded argument summary, answered with an error result, and SHALL classify the session as `attack`. Nothing SHALL be executed.

#### Scenario: Command tool
- **WHEN** a client calls `run_command` with `{"command":"cat /etc/passwd"}`
- **THEN** a command is logged with the tool name and the bounded argument, an alert is raised and an error result is returned

#### Scenario: Injection text in arguments
- **WHEN** an argument contains control characters or a prompt-injection string
- **THEN** control and format characters are replaced, the value is cut to the bound and it is never interpreted

### Requirement: Alert identity
The alert IP SHALL be the socket peer. Header values SHALL only be logged as claimed values.

#### Scenario: Forwarded header
- **WHEN** a request carries `X-Forwarded-For`
- **THEN** it is logged as `claimed_client_ip` and does not change the alert IP
