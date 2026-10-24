## Context

`catchall` and `banner` listen on ports the operator picks, so they have no default port. Until now every trap had an entry in `config.DefaultPorts`, `config.ValidTraps` (derived from it) and `trap.Registry`, and `TestTrapKeySetsMatch` required the three to agree. The README contract test loads the config with every valid trap enabled.

## Decisions

### 1. Addressless traps (task 1.1)

A new map `config.AddresslessTraps` maps the trap name to the variable it requires (`catchall` to `RAN_CATCHALL_ADDR`, `banner` to `RAN_BANNER_SERVICES`). `ValidTraps` is the union of `DefaultPorts` and `AddresslessTraps`, so both names are valid in `RAN_TRAPS`, sorted in error messages and in `ValidTrapNames`. `Load` fails for an enabled addressless trap without its variable and names the variable. Nothing else changed in the generic code: `TrapAddrs` already returns nil for a name without default.

Contract tests: `TestTrapKeySetsMatch` now builds the left side from `DefaultPorts` plus `AddresslessTraps` (and fails if a name is in both), then compares with `ValidTraps` and `Registry`. The README test keeps working because the config test helper supplies a valid value for both variables when it enables all traps, and the two variables are documented in the README. Rejected alternative: placeholder entries in `DefaultPorts` (an empty string). That would weaken the guarantee that every `DefaultPorts` entry is a real listen address.

The Dockerfile `EXPOSE` list is unchanged: there are no default ports to expose, and an `EXPOSE` for guessed ports would be misleading. Operators publish the ports they configure.

### 2. Banner: one TCP skeleton per service

A banner service has its own banner, so the handler must know which service accepted the connection. Looking it up by `conn.LocalAddr()` would work on the real socket, but tests could not use port 0 and the choice would depend on an address that the PROXY protocol path also touches. Instead `BannerTrap` owns one `tcpServer` per service; each has a handler closure that captures its service and an address override (`tcpServer.addrs`, nil for all other traps). All servers share the protocol name `banner`, so the limiter, session timeout (`RAN_BANNER_SESSION_TIMEOUT`), metrics and scan detection treat them as one trap. The configured name is only a log field and alert meta (`service`).

`Start` runs all servers and cancels the others when one fails to bind. Unlike a single multi-address listener this is not strictly all or nothing: a service that bound first can accept a connection for a moment before the failure is noticed. The window is tiny and the connections are closed on cancel; the test checks that the ports are released.

### 3. Banner config syntax

Entries are `port=name:banner`. The first `:` after the name starts the banner, so banners may contain colons. Entries are split on commas that are not escaped, so `\,` is an extra escape beyond the spec text (`\r \n \t \`) that lets a banner contain a comma. Any other escape is an error, a banner is 1 to 256 bytes after decoding, a name is `[a-z0-9_-]` up to 32 bytes, ports are unique, at most 10 entries. Error messages quote the entry (cut at 64 bytes and ASCII-escaped). There is no optional reply string: the proposal text mentioned one, but nothing in the spec used it, so it was dropped.

### 4. Catch-all read window and reads

The trap reads once, at most 256 bytes, with a read deadline of the earlier of 3 seconds and the session deadline. A single `Read` may return fewer bytes than the client sent in its first flight (TLS ClientHello records are cut at 256 bytes anyway); this keeps the trap simple and bounded. The trap sends nothing and closes after the read. A connection closed with unread input may be reset by the peer's TCP stack, which is harmless here.

Sniffer: fixed positions only, checked in this order: `SSH-` prefix, TLS record (`0x16 0x03 0x00..0x04`), SMB over NetBIOS (`0x00`, then `\xffSMB` or `\xfeSMB` at offset 4), RDP (TPKT `03 00` with an X.224 connection request `0xE0` at offset 5), HTTP method followed by a space (or the HTTP/2 preface). Everything else, including empty input, is `unknown`. A silent connect has no sniff label and no payload event: it is a probe with outcome `probe`.

Raw bytes are logged according to `RAN_LOG_PASSWORDS` (this replaces the earlier decision to log them always). The first 256 bytes can contain a secret (an HTTP Authorization or Cookie header, FTP/SMTP/Redis AUTH, a database handshake), so: `off` (default) logs only `sniffed_protocol`, `bytes` and `sha256_prefix` (the first 8 hex characters of the SHA-256 of the captured bytes, enough to correlate repeated payloads); `mask` additionally logs `hex` and `text` as `*** (<length>)`, the same form as masked passwords, with the length in bytes; `on` logs `hex` and `text` (non-printable bytes shown as `.`) and no hash. The mode comes from the package level password mode set from `cfg.LogPasswords`, like every other trap. The alert meta is exactly `{sniffed_protocol, bytes}` in every mode and never carries bytes.

### 5. Banner input

Lines are read with the bounded line reader (512 bytes, at most 100 lines per connection), sanitized like HTTP values, logged as commands with `service` and reported to the sensor once with the command name and the service. A final unterminated line is logged too, so `readLinePartial` was split off `readLineLimited`, which still discards partial data. A line over 512 bytes is logged as a `banner_overlong` payload (it counts as payload bytes) and ends the session with outcome `too_long`. Blank lines are ignored. No data at all is a `probe`.

### 6. Scan detection

No code change in `internal/alert`: the sensor already counts `info.Protocol` and `info.DestPort`, and the skeleton fills `DestPort` from `conn.LocalAddr()` (the real socket, also under PROXY protocol, which only replaces the remote address). The fixed protocol names `catchall` and `banner` count as two protocols; distinct catch-all or banner ports count towards the port rule.

### 7. Banner client lines and secrets

Banner lines are logged as commands, so the existing command redaction applies: `LogCommand` hides the arguments of the credential verbs and markers that the other traps know (`USER`/`PASS` style verbs, `AUTH`, `IDENTIFY`, and so on) according to `RAN_LOG_PASSWORDS`. A banner service can imitate an HTTP-like protocol, so the banner trap additionally hides the value of `Authorization`, `Proxy-Authorization` and `Cookie` lines in the same way (`off` drops the value, `mask` shows `*** (<length>)`, `on` keeps it). The lines are not hashed or blanked as a whole: the command text of a custom service is the data the trap exists to collect, and blanking it would make the trap useless. Limit: a secret in a custom protocol that uses none of these verbs or headers cannot be recognized and is logged; the same limit applies to every other command trap. Overlong lines are never logged (only their size). The alert meta (`command`, `service`) carries only the first token of the first line.

### 8. Non-reading clients

A banner is at most 256 bytes and is written before any read, so it always fits in the socket buffers and the write cannot block on a peer that never reads. Every connection also has the session deadline, so a client that neither reads nor writes ends as a `probe` at `RAN_BANNER_SESSION_TIMEOUT`, and `Stop` closes any live connection. A test covers this; the buffer limit cannot be reached with 256 bytes on loopback, so the write blocking path itself is not exercised.
