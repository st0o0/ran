## 1. Implementation

- [x] 1.1 Certificate helper: generate, persist and load an ECDSA self-signed cert, ephemeral fallback, tests
- [x] 1.2 `tlsfp.go`: ClientHello data (SNI, JA3, JA4) with bounded lists, table tests
- [x] 1.3 `https.go`: trap on the HTTP handler with `tls.Server`, session per connection, handshake timeout from the session deadline
- [x] 1.4 Register in `DefaultPorts`, `ValidTraps`, `Registry`; `RAN_HTTPS_ADDR` and `RAN_HTTPS_CERT_PATH`
- [x] 1.5 README: trap table, config rows (contract test), threat notes

## 2. Tests

- [x] 2.1 Handshake-only, HTTP over TLS, malformed record, oversized ClientHello
- [x] 2.2 Fuzz target `FuzzParseClientHello` (must not panic, bounded output) in `fuzz_test.go` and the AGENTS.md list
- [x] 2.3 `Stop(ctx)` closes live TLS connections; no goroutine leak
- [x] 2.4 `go test -race ./...` in Docker, 386 build, lint, `openspec validate --all`
