## 1. Implementation

- [ ] 1.1 `httppaths.go`: exploit path matcher (exact and prefix tables, case-insensitive, path cleaned), unit tests with a table
- [ ] 1.2 JNDI matcher for request line and a bounded set of header values
- [ ] 1.3 `handleLogin`: log every request (method, path, host, user agent, header subset) with the bounds above
- [ ] 1.4 Record matching requests as commands and alert with `path`, `method`, `user_agent` meta
- [ ] 1.5 Basic `Authorization` parsing as auth attempt, honoring `RAN_LOG_PASSWORDS`
- [ ] 1.6 Non-form bodies counted as payload within the 16 KiB limit
- [ ] 1.7 README: HTTP row, classification notes; AGENTS.md if a convention changes

## 2. Tests

- [ ] 2.1 GET probe stays probe and is summarized; no alert with the default `RAN_BAN_ON`
- [ ] 2.2 Exploit path, JNDI header, Basic auth and JSON body each classify `attack` and alert once
- [ ] 2.3 Spoofed `X-Forwarded-For` still never changes the alert IP
- [ ] 2.4 Fuzz or table test for the matcher: must not panic, bounded output
- [ ] 2.5 `go test -race ./...` in Docker, `go vet` and build for `GOARCH=386`, lint, `openspec validate --all`
