# Log format


Structured JSON to stdout, one line per event:

```json
{
  "time": "2025-01-15T14:23:01Z",
  "level": "INFO",
  "msg": "auth_attempt",
  "protocol": "ssh",
  "session_id": "a1b2c3d4",
  "source_ip": "1.2.3.4",
  "source_port": 54321,
  "action": "auth_attempt",
  "username": "root",
  "password": "admin123"
}
```

Actions: `connect`, `auth_attempt`, `command`, `payload`, `disconnect`,
`probe_summary`, `probe` (fingerprinting events that do not count as an attack),
`rejected` (session limiter) and `error`. TCP connect and disconnect lines are
written for sessions that do something; TCP probe sessions are summarized (see
[Logging of probes](/classification-and-alerts#logging-of-probes)). UDP traps always log `connect` and
`disconnect`.

