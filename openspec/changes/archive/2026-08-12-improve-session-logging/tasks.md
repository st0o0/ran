# Tasks: Improve Session Logging

- [x] Refactor Session struct and NewSession — add DestPort, Logger, activity counters, addr() helper, update NewSession signature
- [x] Rewrite Log methods — LogConnect(DEBUG), LogDisconnect(INFO+summary), LogAuthAttempt/LogCommand/LogPayload with counters and human-readable messages, remove logger parameter
- [x] Update all trap constructors — remove logger.With("trap", ...), store raw logger
- [x] Update all trap handle methods — extract destPort, pass to NewSession, remove logger arg from LogXxx calls
- [x] Update tests — fix any tests for new Session construction and log output
- [x] Update documentation — note breaking change (trap field removed), connect now DEBUG
