## ADDED Requirements

### Requirement: Scanner-based traps enforce maximum line length
Scanner-based traps (FTP, IRC, SMTP, IMAP, POP3, Memcached) SHALL call `scanner.Buffer(make([]byte, limit), limit)` after creating the scanner to enforce a per-line size limit. The limits SHALL be: FTP 512 bytes, IRC 512 bytes, SMTP 512 bytes, IMAP 1024 bytes, POP3 1024 bytes, Memcached 4096 bytes.

#### Scenario: Input within limit is processed normally
- **WHEN** a client sends a command shorter than the trap's limit
- **THEN** the trap reads and processes the command as before

#### Scenario: Input exceeding limit causes scanner error
- **WHEN** a client sends a line longer than the trap's limit
- **THEN** `scanner.Scan()` returns false and `scanner.Err()` returns `bufio.ErrTooLong`
- **THEN** the trap exits the read loop gracefully

### Requirement: Reader-based traps use size-limited buffers
Reader-based traps (Redis, Telnet) SHALL use `bufio.NewReaderSize(conn, limit)` instead of `bufio.NewReader(conn)` with a limit of 4096 bytes.

#### Scenario: Input within limit is processed normally
- **WHEN** a client sends commands shorter than 4096 bytes
- **THEN** the trap reads and processes commands as before

#### Scenario: Oversized input is truncated at buffer boundary
- **WHEN** a client sends a single line longer than 4096 bytes
- **THEN** the reader returns data in chunks up to the buffer size
- **THEN** the trap continues operating without memory exhaustion
