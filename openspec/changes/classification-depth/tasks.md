## 1. Implementation

- [ ] 1.1 Modbus: function code tables, address and quantity parsing with bounds, meta keys
- [ ] 1.2 ADB: read the post-token packet, AUTH key hash, OPEN `shell:`/`exec:` capture, `CLSE` reply
- [ ] 1.3 Telnet: IAC parser (shared helper), replies, TTYPE capture
- [ ] 1.4 mysql, postgres, rdp: retry loop with `ResolveMaxAuthRetries`/`ResolveAuthDelay`; README retry list
- [ ] 1.5 Scan tracker: bounded per-entry port set, threshold constant, tests with an injectable clock
- [ ] 1.6 README classification notes; remove the modbus/adb follow-up from `AGENTS.md`

## 2. Tests

- [ ] 2.1 Table tests for each trap including bounds (oversized quantity, long OPEN destination, long IAC runs)
- [ ] 2.2 Fuzz target for the IAC parser (must not panic, output no longer than input)
- [ ] 2.3 Retry tests with `-count=3` for flakiness
- [ ] 2.4 `go test -race ./...` in Docker, 386 build, lint, `openspec validate --all`
