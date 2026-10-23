## ADDED Requirements

### Requirement: Line reads are length-limited
Telnet, Redis inline commands and PROXY protocol v1 headers SHALL read lines through a helper that returns `bufio.ErrTooLong` once a line exceeds its limit (4096 bytes; 108 bytes for PROXY v1), instead of buffering unbounded data.

#### Scenario: Endless line
- **WHEN** a client sends 1 MiB without a newline to the telnet trap
- **THEN** the read fails with `bufio.ErrTooLong` and the connection is closed

### Requirement: LDAP BER length cap
`berReadLength`, `berReadElement` and `berReadTLV` SHALL reject length encodings over 4 bytes and, in the network readers, lengths above 64 KiB before allocating. Lengths that do not fit a signed `int` on the platform (negative as a 32-bit `int`) SHALL be rejected, as SHALL an NTLMSSP buffer offset that does not fit.

#### Scenario: Huge BER length
- **WHEN** an LDAP client sends tag `0x30` with length bytes `84 FF FF FF FF`
- **THEN** an error is returned and no allocation larger than 64 KiB occurs

#### Scenario: Oversized length encoding in berReadTLV
- **WHEN** `berReadTLV` is given tag `0x30` with length bytes `88 FF FF FF FF FF FF FF FF`
- **THEN** an error is returned

#### Scenario: Negative message ID
- **WHEN** an LDAP client sends the message ID `02 08 FF FF FF FF FF FF FF FF`
- **THEN** the trap answers without panicking and echoes the ID as a valid BER INTEGER

### Requirement: PROXY protocol header handling
With `RAN_PROXY_PROTOCOL` enabled the PROXY header is REQUIRED. It SHALL be read off the accept path under a read deadline (3 seconds), so a silent peer never blocks accepting other connections or closing the listener. A connection that sends no valid v1 or v2 header (other bytes, EOF, or deadline hit) SHALL be closed and counted in `ran_proxy_protocol_dropped_total{protocol}`, and SHALL NOT be handled as a plain connection. At most 1024 handshakes SHALL be pending at once; further connections SHALL be closed immediately and counted, and a handshaken connection that the consumer does not take within 5 seconds SHALL be closed. PROXY v1 SHALL accept only a valid IP address (no zone) and a source port from 0 to 65535. PROXY v2 SHALL require version 2 and an address block of at most 536 bytes. Because any direct peer can forge a header, the mode is only safe when ran is reachable solely from a trusted proxy or tunnel.

#### Scenario: Silent peer does not block others
- **WHEN** one client connects and sends nothing, and a second client sends a valid PROXY header
- **THEN** the second client is accepted without waiting for the first

#### Scenario: Close with a pending connection
- **WHEN** the listener is closed while a connection still waits for its header
- **THEN** `Close` returns promptly and that connection is closed

#### Scenario: Bad port
- **WHEN** a PROXY v1 header carries source port `-5` or `65536`
- **THEN** the connection is closed

#### Scenario: Non-PROXY bytes
- **WHEN** a client sends `GET / HTTP/1.1` as its first bytes
- **THEN** the connection is closed and counted, and never reaches the trap

#### Scenario: Silent peer is dropped
- **WHEN** a client connects and sends nothing for longer than the header deadline
- **THEN** the connection is closed and counted

#### Scenario: Handshake flood
- **WHEN** more silent connections than the pending handshake limit arrive
- **THEN** no more than the limit are pending and the excess is closed immediately and counted

#### Scenario: Stalled consumer
- **WHEN** valid PROXY headers arrive but nothing calls `Accept`
- **THEN** each connection is closed after the handoff timeout and the handshake slot is freed

#### Scenario: Bad PROXY v2 header
- **WHEN** a v2 header has version nibble other than 2, or an address length above 536
- **THEN** the connection is closed

### Requirement: BER INTEGER length
`berReadInteger` SHALL reject a length of 0 or above 8.

#### Scenario: Zero or oversized integer
- **WHEN** an INTEGER has length 0 or length 9
- **THEN** an error is returned
