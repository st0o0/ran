## ADDED Requirements

### Requirement: S7comm trap
The `s7comm` trap SHALL answer a COTP connection request and the S7 setup communication request with valid static responses and a `SZL` read with a fixed identity. Write, download and PLC control functions SHALL be recorded as payload and answered with an error.

#### Scenario: Setup and read
- **WHEN** a client connects, negotiates and reads the module identification
- **THEN** the identity is returned and the session stays a `probe`

#### Scenario: Write attempt
- **WHEN** a client sends a write variable request
- **THEN** a payload is logged with the function code, an alert is raised and the session is `attack`

#### Scenario: Oversized TPKT
- **WHEN** the TPKT length exceeds the limit
- **THEN** the connection is closed without allocating that length

### Requirement: EtherNet/IP trap
The `enip` trap SHALL answer `ListIdentity` and `RegisterSession` with a static identity. `SendRRData` and any unknown command SHALL be payload.

#### Scenario: ListIdentity
- **WHEN** a client sends `ListIdentity`
- **THEN** a static identity item is returned and the session stays a `probe`

### Requirement: PJL trap
The `pjl` trap SHALL answer `@PJL INFO ID` and `@PJL INFO STATUS` with a static identity. Filesystem commands SHALL be recorded as commands and refused. Raw print data SHALL be counted as payload bytes with at most 4096 bytes stored.

#### Scenario: Info query
- **WHEN** a client sends `@PJL INFO ID`
- **THEN** a static printer identity is returned and the session stays a `probe`

#### Scenario: Filesystem listing
- **WHEN** a client sends `@PJL FSDIR NAME="0:\"`
- **THEN** a command is logged and the session is `attack`

### Requirement: IPP trap
The `ipp` trap SHALL answer `Get-Printer-Attributes` with static attributes over HTTP. `Print-Job` SHALL be recorded as a command with job name and size and refused.

#### Scenario: Printer attributes
- **WHEN** a client posts `Get-Printer-Attributes`
- **THEN** a valid IPP response with static attributes is returned and the session stays a `probe`

#### Scenario: Print job
- **WHEN** a client posts `Print-Job` with a document
- **THEN** only job name and size are logged, the document is not stored and the session is `attack`

### Requirement: Registration
`s7comm`, `enip`, `pjl` and `ipp` SHALL be valid trap names with default ports `:102`, `:44818`, `:9100` and `:631`, registered in `DefaultPorts`, `ValidTraps` and `Registry`.

#### Scenario: Enable
- **WHEN** `RAN_TRAPS=s7comm,enip,pjl,ipp` is set
- **THEN** all four traps start on their default ports
