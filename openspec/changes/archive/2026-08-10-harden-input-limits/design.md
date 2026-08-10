## Context

RAN's text-based traps read client input using `bufio.NewScanner` or `bufio.NewReader` with default buffer sizes. While session timeouts limit connection duration, there is no protection against a client sending a single very long line that forces Go to allocate unbounded memory. This is a low-effort DoS vector.

## Goals / Non-Goals

**Goals:**
- Enforce protocol-appropriate maximum input sizes on all 8 text-based traps
- Use RFC-specified limits where standards exist
- Preserve existing trap behavior for well-formed input

**Non-Goals:**
- Centralizing limit configuration (limits are protocol-specific constants)
- Adding metrics or logging for oversized input
- Changing binary/structured protocol traps (SSH, MySQL, RDP, etc.)

## Decisions

### Scanner-based traps: use `scanner.Buffer()`

For traps that use `bufio.NewScanner` (FTP, IRC, SMTP, IMAP, POP3, Memcached), call `scanner.Buffer(make([]byte, limit), limit)` immediately after creating the scanner. This sets both the initial and maximum buffer size.

**Why not `io.LimitReader` wrapping the conn?** `LimitReader` limits total bytes read across the connection lifetime, not per-line. Scanner-based traps need per-line limits, which `scanner.Buffer` provides directly.

### Reader-based traps: use `bufio.NewReaderSize()`

For Redis and Telnet, replace `bufio.NewReader(conn)` with `bufio.NewReaderSize(conn, limit)`. This caps the internal buffer at the specified size. Lines longer than the buffer will be split across multiple reads, which is acceptable since the trap will treat the fragments as separate commands.

**Why not `io.LimitReader`?** Same reasoning: per-read limits are more appropriate than total-bytes limits for interactive protocols. `bufio.NewReaderSize` is the minimal change.

### Limit values

| Trap | Limit | Rationale |
|------|-------|-----------|
| FTP | 512 B | RFC 959 max command line |
| IRC | 512 B | RFC 2812 max message |
| SMTP | 512 B | RFC 5321 max command line |
| IMAP | 1024 B | Conservative protocol limit |
| POP3 | 1024 B | Conservative protocol limit |
| Memcached | 4096 B | Typical key+command size |
| Redis | 4096 B | Typical inline command size |
| Telnet | 4096 B | Generous interactive limit |

## Risks / Trade-offs

- [Truncated input] Legitimate-looking long commands will be silently truncated or error. This is acceptable for a honeypot -- we capture the first N bytes which is sufficient for threat intelligence.
- [Scanner error on oversize] `bufio.Scanner` returns `bufio.ErrTooLong` when a line exceeds the buffer. Traps must handle this gracefully by breaking out of the read loop, which matches existing `scanner.Err()` handling.
