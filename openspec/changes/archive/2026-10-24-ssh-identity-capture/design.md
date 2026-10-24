## Spike result (task 1.1)

Checked `golang.org/x/crypto` v0.58.0 (`ssh/server.go`, `ssh/transport.go`, `ssh/handshake.go`).

- Client version string: available as `ConnMetadata.ClientVersion()` inside every auth callback. The library reads at most 255 bytes of the identification line (`maxVersionStringBytes`) and fails the handshake beyond that.
- Client `KEXINIT` lists: not exposed. There is no `ServerConfig` hook for them (`PreAuthConnCallback` gives a `ServerPreAuthConn`, which only offers banner writing and no access to the peer algorithm lists). The handshake transport parses the packet internally and discards it.

## Chosen approach

A read-only wrapper around the `net.Conn` (`kexSniffConn` in `internal/trap/ssh_identity.go`). `Read` passes bytes through unchanged and copies them into a buffer of at most 16 KiB until the first unencrypted packet after the identification line was parsed (`scanKexInit`). Properties:

- Copy-through only, no effect on the handshake or on writes.
- Bounded: the buffer never grows past 16 KiB, and nothing is allocated from a length field (the packet length is compared with the cap, name lists are only sliced out of the already buffered bytes). Non-`SSH-` lines before the identification line are skipped as the library does.
- Result is a 32 character hex string; any parse problem yields no HASSH (the connection is unaffected).
- The result is read from auth callbacks under a mutex, because the library reads packets on its own goroutine.
- Fuzz target: `FuzzParseKexInit`.

## HASSH

`MD5(kex ";" enc_c2s ";" mac_c2s ";" comp_c2s)`, the client name-lists 1, 3, 5 and 7 (zero based 0, 2, 4, 6) of `SSH_MSG_KEXINIT`, as in the Salesforce HASSH spec. Test vector from `github.com/salesforce/hassh` README ("Example 1", Cyberduck 6.7.1 (28683)): `8a8ae540028bf433cd68356c1b9e8d5b`. The fallback of the proposal (hash of negotiated names) is not needed.

## Other decisions

- `PublicKeyCallback` is invoked once per distinct (user, key) because the library caches the result; each distinct key counts as one failed attempt against `MaxAuthTries` and `RAN_AUTH_DELAY`. Re-offering the same key is not counted again. The library also caps total auth requests at 128 per connection, even when `RAN_MAX_AUTH_RETRIES=0`.
- The keyboard-interactive prompt is a single `Password: ` without echo. The answer is logged as `password` (governed by `RAN_LOG_PASSWORDS`) and is never added to alert meta.
- Alert meta additions: `method`, `client_version`, `hassh`, and for keys `key_type` and `fingerprint`.
