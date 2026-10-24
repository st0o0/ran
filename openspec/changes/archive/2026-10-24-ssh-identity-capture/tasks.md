## 1. Implementation

- [x] 1.1 Spike: can `golang.org/x/crypto/ssh` expose the client `KEXINIT` lists (callback, `ServerConfig` hook or a read-only wrapper around the connection)? Record the result in `design.md`
- [x] 1.2 `PublicKeyCallback` with fingerprint logging, always reject
- [x] 1.3 `KeyboardInteractiveCallback`, always reject
- [x] 1.4 Client version capture and HASSH computation, bounded, table tests against known HASSH vectors
- [x] 1.5 Alert meta keys `client_version` and `hassh`; attempts count against `MaxAuthTries` and `RAN_AUTH_DELAY`
- [x] 1.6 README SSH row and classification notes

## 2. Tests

- [x] 2.1 Key-only client, interactive client and password client in one table test
- [x] 2.2 Limits: unlimited retries (`0`), 3 retries, delay growth with key attempts
- [x] 2.3 Fuzz `FuzzParseKexInit` if a custom parser is needed
- [x] 2.4 `go test -race ./...` in Docker, 386 build, lint, `openspec validate --all`
