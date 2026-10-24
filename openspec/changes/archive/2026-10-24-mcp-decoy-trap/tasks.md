## 1. Implementation

- [x] 1.1 `mcp.go`: JSON-RPC reader with a body limit, method dispatch, static replies
- [x] 1.2 Decoy tool table and argument summarizer (key list, bounded strings, sanitized)
- [x] 1.3 Command and alert recording for `tools/call`; credential headers as auth attempts without storing the value
- [x] 1.4 Register in `DefaultPorts`, `ValidTraps`, `Registry`; README

## 2. Tests

- [x] 2.1 Handshake, list, call, malformed JSON, batch requests (arrays) with a size cap
- [x] 2.2 Fuzz `FuzzParseJSONRPC` (must not panic, output bounded by input)
- [x] 2.3 Sanitizer test with control and format characters
- [x] 2.4 `go test -race ./...` in Docker, 386 build, lint, `openspec validate --all`
