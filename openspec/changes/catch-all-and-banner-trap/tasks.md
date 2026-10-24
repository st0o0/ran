## 1. Implementation

- [ ] 1.1 Decide how traps without a default port fit `DefaultPorts`/`ValidTraps` and the registry contract tests; record in `design.md`
- [ ] 1.2 `catchall.go`: first-byte capture, sniffer with a fixed label set, bounded log
- [ ] 1.3 `banner.go` and config parsing/validation for `RAN_BANNER_SERVICES`
- [ ] 1.4 Metrics label values `catchall` and `banner` only
- [ ] 1.5 README: trap tables, config rows, routing note (ports must be published, no iptables inside)

## 2. Tests

- [ ] 2.1 Sniffer table test (TLS, HTTP, SMB, SSH, RDP, unknown, empty), fuzz `FuzzSniffProtocol`
- [ ] 2.2 Config parsing table (valid, too many, bad port, escapes)
- [ ] 2.3 Scan detection counts both traps as protocols
- [ ] 2.4 `go test -race ./...` in Docker, 386 build, lint, `openspec validate --all`
