## Why

The SSH trap sets only `PasswordCallback`. Public-key and keyboard-interactive attempts are rejected without any log, so key-only bots produce no attack, and the client identity is never recorded. Cowrie records client version, HASSH and offered key fingerprints; they identify the scanning tool independent of the IP.

## What Changes

- `PublicKeyCallback`: every offered key is logged (user, key type, SHA256 fingerprint) as an auth attempt and always rejected.
- `KeyboardInteractiveCallback`: the answers are captured as a credential attempt (password follows `RAN_LOG_PASSWORDS`) and always rejected.
- The client version string is logged and added to alert meta (`client_version`, bounded).
- HASSH (MD5 of the client KEX algorithm lists) is computed from the client `KEXINIT` if the library exposes it, otherwise a documented fallback hashes the negotiated algorithm names. The result is logged and added to alert meta as `hassh`.
- Host key and banner stay as they are.

## Capabilities

### Modified Capabilities

- `trap-ssh`: public-key and keyboard-interactive capture, client identity logging.

## Impact

- `internal/trap/ssh.go`, tests in `ssh_test.go` and `ssh_limits_test.go`; README SSH row (the "password auth only" statement changes).
- Key and interactive attempts count against `RAN_MAX_AUTH_RETRIES` and `RAN_AUTH_DELAY`.

## Non-goals

- No post-auth session: no shell, exec, port forwarding or SFTP (see `todo.md`, Icebox).
- A key or password is never accepted.
- No banner or host key changes.
