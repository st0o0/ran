## ADDED Requirements

### Requirement: Bounded RESP parsing
The Redis trap SHALL reject RESP arrays with more than 128 elements and bulk strings longer than 4096 bytes, SHALL NOT preallocate memory from client-supplied counts or lengths, and SHALL close the connection on violation.

#### Scenario: Huge array count
- **WHEN** a client sends `*2147483647\r\n`
- **THEN** the connection is closed with outcome `error` and no large allocation occurs

#### Scenario: Huge bulk length
- **WHEN** a client sends `*1\r\n$2000000000\r\n`
- **THEN** the connection is closed without allocating the announced size

#### Scenario: Normal AUTH
- **WHEN** a client sends `*2\r\n$4\r\nAUTH\r\n$3\r\nfoo\r\n`
- **THEN** the trap replies `-ERR invalid password` as before
