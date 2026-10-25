## Why

Industrial and printer services are scanned constantly and are cheap to emulate as TCP stubs: S7comm (`102`), EtherNet/IP (`44818`), JetDirect/PJL (`9100`) and IPP (`631`). Conpot, qeeqbox and T-Pot (ipphoney, miniprint) cover them; rán has only Modbus. BACnet and IPMI are UDP and would log only, so they stay out.

## What Changes

- New trap `s7comm` (`:102`): TPKT/COTP connection request and S7 setup communication, `SZL` read answered with minimal static data; write and download requests are payload.
- New trap `enip` (`:44818`): EtherNet/IP `ListIdentity` and `RegisterSession` answered with a static identity; `SendRRData` is payload.
- New trap `pjl` (`:9100`): PJL/JetDirect commands (`@PJL INFO ID`, `@PJL FSDIR`, ...) with a static printer identity; filesystem commands are commands, raw print data is payload (bounded).
- New trap `ipp` (`:631`): IPP over HTTP (`Get-Printer-Attributes`) with static attributes; `Print-Job` is a command (job name and size only).
- Shared TCP skeleton, registry, README, fuzz targets for the binary parsers (`S7`, `ENIP`).

## Capabilities

### New Capabilities

- `trap-ics-printer`: one capability that covers the four traps `s7comm`, `enip`, `pjl` and `ipp`.

### Modified Capabilities

None. The trap names are registered in `DefaultPorts`, `ValidTraps` and `Registry`; the `config-traps-list` capability has no delta in this change.

## Impact

- New files per trap with tests, `config.go`, `registry.go`, README, `AGENTS.md` fuzz list.

## Non-goals

- No UDP ICS protocols (BACnet, IPMI, EtherNet/IP UDP).
- No real PLC state, no write effect, no print job storage.
- No cip/tag database beyond the static identity.
