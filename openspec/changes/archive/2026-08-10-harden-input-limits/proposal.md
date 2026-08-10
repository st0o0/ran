## Why

Text-based traps use default `bufio` buffer sizes (4096 bytes for scanners, 4096 for readers). A malicious client can send arbitrarily long lines to exhaust memory since the only protection is the session timeout. Adding protocol-appropriate input size limits hardens traps against memory exhaustion attacks.

## What Changes

- Scanner-based traps get explicit `scanner.Buffer(make([]byte, limit), limit)` calls with RFC-compliant limits:
  - FTP: 512 bytes (RFC 959)
  - IRC: 512 bytes (RFC 2812)
  - SMTP: 512 bytes (RFC 5321)
  - IMAP: 1024 bytes
  - POP3: 1024 bytes
  - Memcached: 4096 bytes
- Reader-based traps switch to size-limited readers via `bufio.NewReaderSize` or `io.LimitReader`:
  - Redis: 4096 bytes
  - Telnet: 4096 bytes

## Capabilities

### New Capabilities

- `input-size-limits`: Protocol-appropriate input buffer size limits for text-based traps to prevent memory exhaustion

### Modified Capabilities

## Impact

- 8 trap files in `internal/trap/`: `ftp.go`, `irc.go`, `smtp.go`, `imap.go`, `pop3.go`, `memcached.go`, `redis.go`, `telnet.go`
- No API or config changes
- No new dependencies
- Oversized input will be silently truncated or cause a read error, which is acceptable for a honeypot
