## 1. Implementation

- [ ] 1.1 `s7comm.go`: TPKT/COTP/S7 reader with bounded lengths, static setup and SZL replies
- [ ] 1.2 `enip.go`: encapsulation header reader, `ListIdentity`, `RegisterSession`
- [ ] 1.3 `pjl.go`: line reader (bounded), static identity, filesystem commands, raw data counter
- [ ] 1.4 `ipp.go`: minimal IPP attribute reader and writer, `Get-Printer-Attributes`, `Print-Job`
- [ ] 1.5 Register all four in `DefaultPorts`, `ValidTraps`, `Registry`; README and `AGENTS.md` fuzz list

## 2. Tests

- [ ] 2.1 One table test per trap (probe path, attack path, oversized input, `Stop(ctx)`)
- [ ] 2.2 Fuzz targets `FuzzParseS7`, `FuzzParseENIP`, `FuzzParseIPP`
- [ ] 2.3 Registry and README contract tests pass
- [ ] 2.4 `go test -race ./...` in Docker, 386 build, lint, `openspec validate --all`
