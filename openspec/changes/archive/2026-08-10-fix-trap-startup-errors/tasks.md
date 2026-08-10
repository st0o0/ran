## 1. Core Implementation

- [x] 1.1 Add a drain loop after goroutine launch in `run()` that reads `len(traps)` errors from `errc`, logging each non-nil error at `slog.Error` with the trap name
- [x] 1.2 Track the count of failed traps; if all traps failed, cancel context and return an aggregated error
- [x] 1.3 Ensure `run()` only blocks on `ctx.Done()` when at least one trap started successfully

## 2. Testing

- [x] 2.1 Add test: all traps start successfully -- `run()` blocks until context cancellation
- [x] 2.2 Add test: one trap fails -- error is logged, remaining traps continue
- [x] 2.3 Add test: all traps fail -- `run()` returns error immediately

## 3. Verification

- [x] 3.1 Run `go vet ./...` and `go test ./...` with no failures
- [ ] 3.2 Manual smoke test: start ran with one trap bound to an already-used port, confirm error log appears and other traps run
