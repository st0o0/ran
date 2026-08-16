## 1. Alert Types and Interface

- [x] 1.1 Add `csEvent` struct (fields: `Timestamp string`, `Meta []csMeta`) and `csMeta` struct (fields: `Key string`, `Value string`) to `internal/alert/crowdsec.go`
- [x] 1.2 Add `Events []csEvent` field to `csAlert` struct with json tag `"events"`
- [x] 1.3 Change `Alerter` interface in `internal/alert/alerter.go` to `Alert(ctx context.Context, ip string, protocol string, meta map[string]string)`
- [x] 1.4 Update `NoopAlerter.Alert` signature to accept the new `meta` parameter
- [x] 1.5 Update `alertMsg` struct to carry `Meta map[string]string` and pass it through the channel in `Alert()` and `push()`

## 2. Payload Construction

- [x] 2.1 In `push()`, build a `csEvent` from `msg.Meta`: convert `map[string]string` to `[]csMeta` sorted by key, set timestamp to match `start_at`. If meta is nil, use empty `[]csMeta{}`
- [x] 2.2 Set `alerts[0].Events` to `[]csEvent{event}` — always a non-nil single-element slice
- [x] 2.3 Change `Source.Scope` from `"ip"` to `"Ip"` in the alert source
- [x] 2.4 Change `Decisions[].Scope` from `"ip"` to `"Ip"` in the ban decision

## 3. Trap Call Sites

- [x] 3.1 Update `internal/trap/ssh.go` — pass `map[string]string{"username": c.User(), "password": string(pass)}`
- [x] 3.2 Update `internal/trap/http.go` — pass username, password
- [x] 3.3 Update `internal/trap/httpproxy.go` — pass username, password, command (3 call sites)
- [x] 3.4 Update `internal/trap/mysql.go` — pass username, password
- [x] 3.5 Update `internal/trap/mssql.go` — pass username, password
- [x] 3.6 Update `internal/trap/ftp.go` — pass username, password
- [x] 3.7 Update `internal/trap/imap.go` — pass username, password
- [x] 3.8 Update `internal/trap/pop3.go` — pass username, password
- [x] 3.9 Update `internal/trap/irc.go` — pass nick (as username), password
- [x] 3.10 Update `internal/trap/ldap.go` — pass username (bind DN), password
- [x] 3.11 Update `internal/trap/redis.go` — pass password
- [x] 3.12 Update `internal/trap/rdp.go` — pass username
- [x] 3.13 Update `internal/trap/smb.go` — pass username, domain, workstation
- [x] 3.14 Update `internal/trap/mqtt.go` — pass client_id, username, password
- [x] 3.15 Update `internal/trap/oracle.go` — pass username, service_name
- [x] 3.16 Update `internal/trap/elasticsearch.go` — pass command (3 call sites)
- [x] 3.17 Update `internal/trap/dns.go` — pass domain, qtype
- [x] 3.18 Update `internal/trap/ntp.go` — pass version, mode
- [x] 3.19 Update `internal/trap/modbus.go` — pass function_code
- [x] 3.20 Update `internal/trap/memcached.go` — pass nil

## 4. Remaining Traps

- [x] 4.1 Grep for any remaining `alerter.Alert(` calls not yet updated (smtp, telnet, socks5, vnc, postgres, sip, etc.) and update each to pass metadata or nil

## 5. Tests

- [x] 5.1 Update all `Alert()` calls in `internal/alert/crowdsec_test.go` to include the 4th `meta` parameter
- [x] 5.2 Add test: assert marshalled JSON contains `"events"` array with populated meta when metadata is provided
- [x] 5.3 Add test: assert marshalled JSON contains `"events"` array with empty meta when nil is passed
- [x] 5.4 Add test: assert `source.scope` is `"Ip"` and `decisions[].scope` is `"Ip"` in the payload
- [x] 5.5 Update any trap tests that call `Alert()` to pass the new parameter (grep for `.Alert(` in `internal/trap/*_test.go`)
- [x] 5.6 Run `go build ./...` and `go test ./...` — verify zero failures
