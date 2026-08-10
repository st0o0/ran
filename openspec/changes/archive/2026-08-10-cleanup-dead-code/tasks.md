## 1. Remove unused WaitGroup from HTTPTrap

- [x] 1.1 Remove `wg sync.WaitGroup` field from `HTTPTrap` struct in `internal/trap/http.go`
- [x] 1.2 Remove `t.wg.Wait()` call from `HTTPTrap.Stop()` method
- [x] 1.3 Remove `sync` import if no longer used

## 2. Replace custom readFull in RDP trap

- [x] 2.1 Replace calls to `readFull(conn, buf)` with `io.ReadFull(conn, buf)` in `internal/trap/rdp.go`
- [x] 2.2 Delete the `readFull` function definition (lines 166-176)
- [x] 2.3 Ensure `io` is in the import list

## 3. Graceful metrics server shutdown

- [x] 3.1 In `cmd/ran/main.go`, replace `metricsSrv.Close()` with `metricsSrv.Shutdown(ctx)` using a 5-second `context.WithTimeout`
- [x] 3.2 Ensure `context` is imported

## 4. Verify

- [x] 4.1 Run `go build ./...` to confirm compilation
- [x] 4.2 Run `go vet ./...` to check for issues
