## Context

Four TCP stubs for industrial and printer services. `s7comm`, `enip` and `pjl` run on the shared TCP skeleton (`tcpserver.go`); `ipp` embeds the HTTP trap like `docker` and `kubernetes`, so listening, PROXY trust, per-connection sessions, limits and `Stop(ctx)` come from existing code.

## Static identities, no seeded variation

The `fingerprint-realism` change gives banner traps a per-instance seeded profile so that a fleet of sensors is hard to fingerprint by one banner. The ICS and printer traps deliberately do not use it: scanners (nmap `s7-info`, `enip-info`, Shodan) compare identities with device databases, and a randomly assembled module name, vendor id or serial prefix looks less plausible than one consistent device. Each trap therefore answers with one fixed identity per protocol (a Siemens-like CPU, an Allen-Bradley-like PLC, an HP-like LaserJet). Everything that identifies a unit (serial numbers, MAC-like values, addresses) is invented, and the same model string is used by `pjl` and `ipp`. Nothing in any response is derived from the request except protocol-required echoes (COTP source reference, ENIP sender context, IPP request id and version family).

## Protocol subsets

**s7comm.** TPKT (RFC 1006, version 3, length 16 bit big endian, total capped at 1024) then COTP: connection request (`0xE0`) is answered with a connection confirm with fixed TSAPs, disconnect request ends the session, data (`0xF0`) carries an S7 PDU. S7: job `setup communication (0xF0)` is answered with an ack-data of one job each way and PDU size 480; `read var (0x04)` is answered with an S7 error (fingerprinting); userdata SZL read (group 4, subfunction 1) is answered from a fixed table (`0x0011` module identification, `0x001C` component identification; other ids get the object-not-found return code); userdata group 3 (block functions) is read only and answered with an error. `write var (0x05)` is `write`; download (`0x1A` to `0x1C`), upload (`0x1D` to `0x1F`), PLC control (`0x28`) and stop (`0x29`) are `control`; everything else is `unknown`. Bounds: the declared TPKT length is checked with `fitsInt` before `make`; the S7 parameter length is checked against the bytes in hand; at most 64 packets per session.

**enip.** 24 byte encapsulation header, little endian, data length capped at 1024 before allocation. `ListIdentity` returns one CIP identity item; `ListServices` one "Communications" service; `ListInterfaces` zero items; `RegisterSession` returns the fixed handle `0x0001A2B3`; `UnRegisterSession` closes; `NOP` is ignored. `SendRRData` and `SendUnitData` are `send_data`; the CIP service code is read from the unconnected or connected data item with bounds checks on at most four items. Unknown commands are `unknown`. Both attack kinds are answered with status `0x0001`. At most 64 packets per session.

**pjl.** A bufio reader with a 1024 byte buffer delivers chunks that end at a newline or after 1024 bytes, so no read is unbounded and binary data without newlines is chunked. UEL (`ESC %-12345X`) is stripped. A chunk whose trimmed text starts with `@PJL` is a command; verb and `INFO` category are matched against fixed lists, so responses and logged verbs never contain client text. Everything else is print data: consecutive chunks form one run that keeps its length, a running SHA-256 and the first 64 bytes. The run is logged and alerted once when it ends (next PJL command, EOF, limit). The log sample replaces non-printable bytes and goes through the secret scrubber; alert meta carries only length and hash. `@PJL ECHO` is answered with an empty echo (no reflection). Limits: 64 KiB read per session (`too_long` beyond), 64 PJL commands.

**ipp.** POST bodies are parsed as IPP (version 1.0 to 2.2, operation, request id, attribute groups, end tag). Names are capped at 255 bytes, at most 64 attributes are inspected, every offset is bounds checked and only the `job-name` value (64 bytes, valid UTF-8) is kept. The document starts after the end tag; its size is the body length after that offset, or `Content-Length` minus the offset when the 16 KiB body limit cut the read. Responses are built from two precomputed byte slices (operation attributes, printer attributes) plus the version, status and request id.

## Kind vocabularies

Alert `kind` (closed, never client data): `s7comm` write, control, unknown; `enip` send_data, unknown; `pjl` fs_command, set, other, print_data; `ipp` print_job, other. Probe log lines carry the probe vocabulary: `s7comm` connect, setup, identify; `enip` list_identity, list_services, list_interfaces, register_session, unregister_session, nop; `pjl` info, job; `ipp` attributes. An IPP request that is not IPP and a non-POST method use `other`.

## Alert meta key sets

`s7comm`: `kind`, plus `function_code` when an S7 job function was decoded. `enip`: `kind`, `command_code`, plus `cip_service` when found. `pjl` commands: `kind`, `command` (sanitized, scrubbed, 256 bytes); print data: `kind`, `data_bytes`, `data_hash`. `ipp`: `path`, `method`, `user_agent`, `command`, `kind`, plus `operation`, `document_bytes` and `job_name` (when present) for IPP requests. Sensor keys are added by the sensor. No key can hold a password or document content.

## Decisions

- Probe versus attack follows the existing rule: only payload, command or auth counts make an attack. Identification (SZL, ListIdentity, PJL INFO, IPP attributes) never does.
- `pjl` print data is an attack even when it is a legitimate-looking document, because an unauthenticated print job on a honeypot is not benign.
- IPP answers print operations with HTTP 200 and an IPP status, like CUPS, instead of an HTTP error, so clients keep parsing the body.
- Metric labels are the fixed protocol names `s7comm`, `enip`, `pjl`, `ipp`.
