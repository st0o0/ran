## 1. Implementation

- [ ] 1.1 `mcp.go`: JSON-RPC reader with a body limit, method dispatch, static replies
- [ ] 1.2 Decoy tool table and argument summarizer (key list, bounded strings, sanitized)
- [ ] 1.3 Command and alert recording for `tools/call`; credential headers as auth attempts without storing the value
- [ ] 1.4 Register in `DefaultPorts`, `ValidTraps`, `Registry`; README

## 2. Tests

- [ ] 2.1 Handshake, list, call, malformed JSON, batch requests (arrays) with a size cap
- [ ] 2.2 Fuzz `FuzzParseJSONRPC` (must not panic, output bounded by input)
- [ ] 2.3 Sanitizer test with control and format characters
- [ ] 2.4 `go test -race ./...` in Docker, 386 build, lint, `openspec validate --all`
