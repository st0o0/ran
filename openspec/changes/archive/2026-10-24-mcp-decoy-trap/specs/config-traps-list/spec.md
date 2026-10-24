## ADDED Requirements

### Requirement: MCP trap
`mcp` SHALL be a valid trap name with default port `:8000`, registered in `DefaultPorts`, `ValidTraps` and `Registry`.

#### Scenario: Enable
- **WHEN** `RAN_TRAPS=mcp` is set
- **THEN** the trap starts on `:8000` and appears in `/healthz`
