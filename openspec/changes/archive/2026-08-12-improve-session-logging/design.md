# Design: Improve Session Logging

## Session struct changes

```go
type Session struct {
    ID           string
    Protocol     string
    SourceIP     string
    Port         int
    DestPort     int
    Start        time.Time
    Logger       *slog.Logger

    authAttempts int
    commands     int
    payloads     int
}
```

`NewSession` gains a `destPort` parameter and creates the session-scoped logger:

```go
func NewSession(protocol, sourceIP string, port, destPort int, logger *slog.Logger) *Session {
    s := &Session{
        ID:       uuid.NewString(),
        Protocol: protocol,
        SourceIP: sourceIP,
        Port:     port,
        DestPort: destPort,
        Start:    time.Now(),
    }
    s.Logger = logger.With(
        "protocol", protocol,
        "session_id", s.ID,
        "source_ip", sourceIP,
        "source_port", port,
        "dest_port", destPort,
    )
    return s
}
```

## Message format

Each log method builds a human-readable message string and passes it as the slog message. The `addr` helper formats `ip:port` consistently:

```go
func (s *Session) addr() string {
    return net.JoinHostPort(s.SourceIP, strconv.Itoa(s.Port))
}
```

## Log methods

### LogConnect (DEBUG)

```go
func (s *Session) LogConnect() {
    s.Logger.Debug(
        fmt.Sprintf("%s connect from %s", s.Protocol, s.addr()),
        "action", "connect",
    )
}
```

### LogDisconnect (INFO, with summary)

```go
func (s *Session) LogDisconnect() {
    dur := time.Since(s.Start)
    s.Logger.Info(
        fmt.Sprintf("%s disconnect from %s duration=%dms auth=%d cmd=%d",
            s.Protocol, s.addr(), dur.Milliseconds(), s.authAttempts, s.commands),
        "action", "disconnect",
        "duration_ms", dur.Milliseconds(),
        "auth_attempts", s.authAttempts,
        "commands", s.commands,
        "payloads", s.payloads,
    )
}
```

### LogAuthAttempt (INFO, increments counter)

```go
func (s *Session) LogAuthAttempt(attrs ...slog.Attr) {
    s.authAttempts++
    // build human-readable msg from attrs (extract "username" if present)
    msg := fmt.Sprintf("%s auth from %s", s.Protocol, s.addr())
    for _, a := range attrs {
        if a.Key == "username" {
            msg += fmt.Sprintf(" user=%s", a.Value.String())
            break
        }
    }
    args := make([]any, 0, 1+len(attrs))
    args = append(args, slog.String("action", "auth_attempt"))
    for _, a := range attrs {
        args = append(args, a)
    }
    s.Logger.Info(msg, args...)
}
```

### LogCommand (INFO, increments counter)

```go
func (s *Session) LogCommand(command string, attrs ...slog.Attr) {
    s.commands++
    msg := fmt.Sprintf("%s command from %s cmd=%s", s.Protocol, s.addr(), command)
    // ... structured fields as before, action="command"
}
```

### LogPayload (INFO, increments counter)

```go
func (s *Session) LogPayload(payloadType string, attrs ...slog.Attr) {
    s.payloads++
    msg := fmt.Sprintf("%s payload from %s type=%s", s.Protocol, s.addr(), payloadType)
    // ... structured fields as before, action="payload"
}
```

## Caller changes

### Trap constructors — remove `logger.With("trap", ...)`

Before:
```go
logger: logger.With("trap", "smb"),
```

After:
```go
logger: logger,
```

### Handle methods — pass dest_port, use session logger

Before:
```go
sess := NewSession("smb", host, port)
sess.LogConnect(t.logger)
defer sess.LogDisconnect(t.logger)
// ...
sess.LogAuthAttempt(t.logger, slog.String("username", user))
```

After:
```go
_, destPort := ParseAddr(t.listener.Addr().String())
sess := NewSession("smb", host, port, destPort, t.logger)
sess.LogConnect()
defer sess.LogDisconnect()
// ...
sess.LogAuthAttempt(slog.String("username", user))
```

The listener's local address provides `dest_port`. All traps already store their listener.

## Thread safety

Session counters (`authAttempts`, `commands`, `payloads`) are only accessed within a single goroutine (the connection handler). No synchronization needed.

## Migration impact

| Query pattern | Status |
|---|---|
| `action="connect"` | works, but only visible at DEBUG |
| `action="disconnect"` | works, now richer |
| `action="auth_attempt"` | works unchanged |
| `trap="smb"` | **broken** — migrate to `protocol="smb"` |
| `protocol="smb"` | works unchanged |
