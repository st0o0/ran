## Why

AI agents and MCP servers are a new scan target: exposed MCP endpoints are probed for tools, and 2026 honeypot reports describe real exploitation attempts. Beelzebub offers MCP decoys, but nobody ties them to a blocklist. A static decoy fits the existing stub style of rán and gives CrowdSec a signal for sources that call agent tools.

## What Changes

- New trap `mcp` (default `:8000`): JSON-RPC 2.0 over HTTP (`POST /mcp`, plus `GET /sse` answered as a closed stream), answering `initialize`, `ping` and `tools/list` with a fixed set of inert bait tools (for example `read_file`, `run_command`, `get_secrets`).
- `tools/call` is recorded as a command: tool name and a bounded, sanitized argument summary (keys and the first 128 bytes of each string), answered with a plausible error result. Nothing is executed.
- `initialize` and `tools/list` alone stay a `probe`. A `tools/call` or a credential header is an `attack`.
- All client text is treated as untrusted: control and format characters stripped, lengths capped, never interpreted, never forwarded to any model.

## Capabilities

### New Capabilities

- `trap-mcp`.

### Modified Capabilities

- `config-traps-list`: `mcp` added with default port `:8000`.

## Impact

- New `mcp.go` (+ tests, fuzz for the JSON-RPC reader), `config.go`, `registry.go`, README. Reuses the HTTP session pattern.

## Non-goals

- No LLM, no tool execution, no file access, no outbound requests.
- No MCP resources, prompts or sampling beyond static empty lists.
- No OAuth flows.
