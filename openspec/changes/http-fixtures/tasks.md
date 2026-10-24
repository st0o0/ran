## 1. Implementation

- [ ] 1.1 Fixture table (path match rules, status, headers, body), no request data in bodies
- [ ] 1.2 Wire into `handleLogin` after request logging and classification
- [ ] 1.3 `RAN_HTTP_FIXTURES` loader and validation (entry count, body size, header allow-list), `check-config` output
- [ ] 1.4 README: HTTP row, config row (contract test)

## 2. Tests

- [ ] 2.1 Each built-in fixture returns the expected status and headers
- [ ] 2.2 Reflection test: no request bytes in any fixture response
- [ ] 2.3 Loader table test (valid, too many, too large, bad header, duplicate path)
- [ ] 2.4 `go test -race ./...` in Docker, 386 build, lint, `openspec validate --all`
