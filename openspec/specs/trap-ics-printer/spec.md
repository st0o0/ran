# trap-ics-printer Specification

## Purpose
Provide low-interaction TCP stubs of industrial and printer services that scanners probe constantly (S7comm on port 102, EtherNet/IP on 44818, JetDirect/PJL on 9100 and IPP on 631): each answers identification requests with one fixed, plausible device identity and records write, control, filesystem and print attempts as bounded payload or commands, so that scanners and noise stay probes and only real attempts raise alerts.
## Requirements
### Requirement: S7comm trap
The `s7comm` trap SHALL answer a COTP connection request and the S7 setup communication request with valid static responses and an `SZL` read (module identification `0x0011`, component identification `0x001C`) with a fixed, invented identity. Read variable requests, block-function userdata (group 3) and the read-clock userdata functions (group 7, subfunctions 1 and 3) SHALL be answered with an S7 error and stay a probe. The COTP PDU type SHALL be compared by its high nibble. Write variable, block download and upload, PLC control and stop, and any unknown function SHALL be recorded as payload, answered with an S7 error and raise an alert whose `kind` is `write`, `control` or `unknown`. The identity SHALL be static, not seeded.

#### Scenario: Setup and read
- **WHEN** a client connects, negotiates and reads the module identification
- **THEN** the identity is returned and the session stays a `probe`

#### Scenario: Write attempt
- **WHEN** a client sends a write variable request
- **THEN** a payload is logged with the function code, an alert with `kind` `write` and `function_code` is raised, an S7 error is returned and the session is `attack`

#### Scenario: Oversized TPKT
- **WHEN** the TPKT length exceeds 1024 bytes
- **THEN** the connection is closed with outcome `too_long` without allocating that length

#### Scenario: Cross-protocol noise
- **WHEN** the first four bytes are not a TPKT header (an HTTP request line, a TLS hello, an SSH banner, blank lines or any other bytes)
- **THEN** they are logged with a `sniffed_protocol` label, no alert is raised, nothing is answered, the connection is closed and the session stays a `probe`

#### Scenario: Not TPKT after valid traffic
- **WHEN** bytes that are not a TPKT header arrive after a valid packet, or a TPKT header declares a length below the minimum
- **THEN** they are logged as payload, an alert with `kind` `unknown` is raised and the connection is closed

### Requirement: EtherNet/IP trap
The `enip` trap SHALL answer `ListIdentity`, `ListServices`, `ListInterfaces` and `RegisterSession` with static data (a fixed session handle for `RegisterSession`). `NOP` SHALL be ignored. `SendRRData`, `SendUnitData` and any unknown command SHALL be payload, answered with an encapsulation status, and raise an alert whose `kind` is `send_data` or `unknown`. The encapsulation data length SHALL be bounded to 1024 bytes.

#### Scenario: ListIdentity
- **WHEN** a client sends `ListIdentity`
- **THEN** a static identity item is returned and the session stays a `probe`

#### Scenario: SendRRData
- **WHEN** a client sends `SendRRData`
- **THEN** a payload is logged with the command code and the CIP service code, an alert with `kind` `send_data` is raised and the session is `attack`

#### Scenario: Oversized data
- **WHEN** the declared data length exceeds 1024 bytes
- **THEN** the connection is closed with outcome `too_long` without allocating that length

### Requirement: PJL trap
The `pjl` trap SHALL answer `@PJL INFO ID|STATUS|CONFIG|VARIABLES|USTATUS|FILESYS` with static text that contains nothing from the request, and `@PJL ECHO <text>` with the same text cut to printable ASCII and at most 32 bytes (the only reflection). Lines SHALL end with CR, LF or CRLF, and a UEL sequence SHALL be stripped also when it is split across two reads. A first chunk that is HTTP, TLS, SMB, SSH or RDP traffic SHALL be a `probe`: logged with its `sniffed_protocol` label, not answered and not counted as print data. Filesystem commands SHALL be recorded as commands (`kind` `fs_command`) and refused. `SET`, `DEFAULT` and similar commands SHALL be recorded as commands (`kind` `set`) and refused. Raw print data SHALL be counted as payload bytes; only its length, a SHA-256 prefix and a printable prefix of at most 64 bytes SHALL be logged and none of it stored. The session SHALL read at most 64 KiB and serve at most 64 PJL commands.

#### Scenario: Info query
- **WHEN** a client sends `@PJL INFO ID`
- **THEN** a static printer identity is returned and the session stays a `probe`

#### Scenario: Filesystem listing
- **WHEN** a client sends `@PJL FSDIR NAME="0:\"`
- **THEN** a command is logged, an alert with `kind` `fs_command` is raised and the session is `attack`

#### Scenario: Cross-protocol noise
- **WHEN** a client sends an HTTP request line to the printer port
- **THEN** it is logged with `sniffed_protocol` `http`, no print data is counted and the session is a `probe`

#### Scenario: Print data
- **WHEN** a client sends PostScript or PCL data after the PJL header
- **THEN** a payload with length, hash prefix and a sanitized 64 byte prefix is logged, an alert with `kind` `print_data` is raised and the data is not stored

### Requirement: IPP trap
The `ipp` trap SHALL answer `Get-Printer-Attributes` over HTTP with a valid IPP response of static attributes (advertising IPP 1.0, 1.1, 2.0, 2.1 and 2.2 and a static `printer-up-time`), `Get-Jobs` and `Validate-Job` with a successful response and `Get-Job-Attributes` with `client-error-not-found`, all as a probe (a JNDI string in such a request makes it a command with `kind` `other`); no value of the request SHALL appear in a response. `Print-Job`, `Create-Job`, `Send-Document` and `Send-URI` SHALL be recorded as a command (`kind` `print_job`) with the operation, the job name (bounded) and the document size only, and refused with `client-error-not-authorized`. The document size SHALL be the bytes after the end-of-attributes tag, or the declared `Content-Length` minus the attribute bytes when the body was cut, clamped to 2 GiB; no declared value SHALL be added unbounded to the session payload counter. Every other operation SHALL be recorded as a command (`kind` `other`) and refused with `server-error-operation-not-supported`. Read-only HTTP methods SHALL stay a probe; other methods and a `POST` that is not IPP SHALL be commands.

#### Scenario: Printer attributes
- **WHEN** a client posts `Get-Printer-Attributes`
- **THEN** a valid IPP response with static attributes is returned and the session stays a `probe`

#### Scenario: Print job
- **WHEN** a client posts `Print-Job` with a document
- **THEN** only operation, job name and document size are logged, the document is not stored, the answer is `client-error-not-authorized` and the session is `attack`

#### Scenario: Plain GET
- **WHEN** a client sends `GET /` to the IPP port
- **THEN** a static page is returned and the session stays a `probe`

### Requirement: Registration
`s7comm`, `enip`, `pjl` and `ipp` SHALL be valid trap names with default ports `:102`, `:44818`, `:9100` and `:631`, registered in `DefaultPorts`, `ValidTraps` and `Registry`. Their protocol names SHALL count as distinct protocols and their ports as distinct destination ports for scan detection, and sources in the ignore list SHALL leave no event or tracking state.

#### Scenario: Enable
- **WHEN** `RAN_TRAPS=s7comm,enip,pjl,ipp` is set
- **THEN** all four traps start on their default ports

