## 1. Implementation

- [x] 1.1 `docker.go`: HTTP stub on the shared HTTP pattern (session per connection), static JSON, create/exec recorded and refused
- [x] 1.2 `kubernetes.go`: API and kubelet stub, token hash prefix, exec paths refused
- [x] 1.3 `mongodb.go`: BSON-lite reader with bounded lengths, `OP_MSG` and `OP_QUERY`, handshake replies, `Unauthorized` for the rest
- [x] 1.4 Register all three in `DefaultPorts`, `ValidTraps`, `Registry`; telnet default `:23,:2323` (check multi-port bind failure behavior first)
- [x] 1.5 README: trap tables, config rows (contract test), Dockerfile ports if present

## 2. Tests

- [x] 2.1 One table test per trap: probe path, attack path, oversized input, `Stop(ctx)`
- [x] 2.2 Fuzz targets `FuzzReadMongoMessage`, `FuzzParseDockerBody` and `FuzzFormCommand` in `fuzz_test.go` and the AGENTS.md list
- [x] 2.3 Registry and README contract tests pass
- [x] 2.4 `go test -race ./...` in Docker, 386 build, lint, `openspec validate --all`
