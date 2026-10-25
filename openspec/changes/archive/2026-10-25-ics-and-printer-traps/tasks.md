## 1. Implementation

- [x] 1.1 `s7comm.go`: TPKT/COTP/S7 reader with bounded lengths, static setup and SZL replies
- [x] 1.2 `enip.go`: encapsulation header reader, `ListIdentity`, `RegisterSession`
- [x] 1.3 `pjl.go`: line reader (bounded), static identity, filesystem commands, raw data counter
- [x] 1.4 `ipp.go`: minimal IPP attribute reader and writer, `Get-Printer-Attributes`, `Print-Job`
- [x] 1.5 Register all four in `DefaultPorts`, `ValidTraps`, `Registry`; README and `AGENTS.md` fuzz list

## 2. Tests

- [x] 2.1 One table test per trap (probe path, attack path, oversized input, `Stop(ctx)`)
- [x] 2.2 Fuzz targets `FuzzParseS7`, `FuzzParseENIP`, `FuzzParseIPP`
- [x] 2.3 Registry and README contract tests pass
- [x] 2.4 `go test -race ./...` in Docker, 386 build, lint, `openspec validate --all`
