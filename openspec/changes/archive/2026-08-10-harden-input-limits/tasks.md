## 1. Scanner-based traps (512-byte limit)

- [x] 1.1 Add `scanner.Buffer(make([]byte, 512), 512)` after `bufio.NewScanner` in `internal/trap/ftp.go`
- [x] 1.2 Add `scanner.Buffer(make([]byte, 512), 512)` after `bufio.NewScanner` in `internal/trap/irc.go`
- [x] 1.3 Add `scanner.Buffer(make([]byte, 512), 512)` after `bufio.NewScanner` in `internal/trap/smtp.go`

## 2. Scanner-based traps (1024-byte limit)

- [x] 2.1 Add `scanner.Buffer(make([]byte, 1024), 1024)` after `bufio.NewScanner` in `internal/trap/imap.go`
- [x] 2.2 Add `scanner.Buffer(make([]byte, 1024), 1024)` after `bufio.NewScanner` in `internal/trap/pop3.go`

## 3. Scanner-based traps (4096-byte limit)

- [x] 3.1 Add `scanner.Buffer(make([]byte, 4096), 4096)` after `bufio.NewScanner` in `internal/trap/memcached.go`

## 4. Reader-based traps (4096-byte limit)

- [x] 4.1 Replace `bufio.NewReader(conn)` with `bufio.NewReaderSize(conn, 4096)` in `internal/trap/redis.go`
- [x] 4.2 Replace `bufio.NewReader(conn)` with `bufio.NewReaderSize(conn, 4096)` in `internal/trap/telnet.go`

## 5. Verification

- [x] 5.1 Run `go build ./...` to confirm no compilation errors
- [x] 5.2 Run `go test ./...` to confirm existing tests pass
