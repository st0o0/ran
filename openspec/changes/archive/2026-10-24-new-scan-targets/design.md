## Context

Three new targets (Docker, Kubernetes, MongoDB) and a second telnet port. Two of them speak HTTP, one a binary protocol.

## Decisions

### HTTP reuse for docker and kubernetes

`DockerTrap` and `KubernetesTrap` embed `*HTTPTrap` (built with `newHTTPTrap(proto, ...)`) and replace only the handler through `setHandler`. Listening, `ConnContext`/`ConnState` sessions keyed by the connection, the limiter, timeouts, `MaxHeaderBytes` and `Stop` (which closes live connections) therefore exist once. A small `stubRequest` helper (`apistub.go`) builds the bounded log attributes, alert meta (`path`, `method`, `user_agent`, `command`), the JNDI check and the body read (16 KiB) for both stubs.

The `http` trap handler itself is not reused: it answers every request with a login page and classifies by exploit path, which does not fit an API stub (`/containers/json` is even on the exploit path list).

Classification: read-only requests (`GET`, `HEAD`, `OPTIONS`) to known endpoints are probes (`Session.Log`); create/exec, any other method, JNDI and a request body count as command or payload and raise an alert. Bodies are not logged; only the parsed `Image`/`Cmd` of a create or exec, cut to 256 bytes, reach the log and the alert meta.

The bearer token is hashed (SHA-256, first 8 hex characters) before it is used anywhere; `Authorization` is never in the logged header subset.

### MongoDB reader bounds

The wire protocol allows 48 MB per message; the sensor needs the handshake and the first command only. `readMongoMessage` reads the 16 byte header, converts the length with `fitsInt`, rejects anything above 64 KiB or below 16 before reading, and collects the body with `io.ReadAll(io.LimitReader(...))`, so memory follows the bytes that actually arrive, never the declared length.

The BSON walk is top level only: nested documents, arrays and every other value are skipped by their declared size (checked against the remaining bytes with comparisons that cannot overflow a 32-bit `int`). It stops after 64 elements. There is no recursion, hence no depth to cap. Only the strings `$db`, `mechanism`, `user` and the binary `payload` are read; the SASL payload is cut to 1 KiB and only its user name leaves the parser.

`ping` is answered as a handshake command (drivers send it right after `hello`) even though the original spec named only `hello`/`isMaster` and `buildInfo`. `saslStart` is answered with `AuthenticationFailed` at once instead of continuing the SCRAM conversation, which avoids any crypto and keeps proofs out of the sensor.

### Telnet multi-port

`ListenMultiTCP` is all or nothing (documented by the `multi-port-listener` spec): when one address cannot be bound the others are closed and `Start` returns the error. With the new default `:23,:2323` a host where `:2323` is taken therefore no longer starts telnet. This is kept on purpose: partial binding for explicit configuration would hide typos, and changing the listener for one default would need a new "optional address" concept. The failure is loud (`trap failed to start` with the address) and the README names the remedy (`RAN_TELNET_ADDR`). The behavior is covered by `TestTelnetMultiPortBindFailureIsAllOrNothing`.

## Risks

- A deployment that already used `:2323` for something else loses telnet until `RAN_TELNET_ADDR` is set.
- The Kubernetes stub speaks plain HTTP; real clients use TLS and will fail the handshake on `:6443` (non-goal, follows `tls-traps`).

## Review follow-ups

- Methods: `GET`, `HEAD` and `OPTIONS` are read-only for docker and kubernetes (`isReadOnlyMethod`), so a crawler's `OPTIONS` is a probe. `POST`, `PUT`, `PATCH` and `DELETE` change state and are attacks. `PROPFIND`, `CONNECT`, `TRACE` and unknown methods are not part of either API and are treated as attacks too, because nothing legitimate sends them to a container API.
- SASL PLAIN: only the full `authzid NUL authcid NUL passwd` form is parsed (the `authcid` is taken). Every other shape yields no user name, so a two part payload can never put the password into the `username` log field or alert meta.
- Docker create: the image name is cut to 64 bytes at a rune boundary so the `cmd` part is not pushed out of the 256 byte command meta. Meta values are cut at rune boundaries (`truncateRunes`) so they stay valid UTF-8.
- The fuzz target for the BSON message reader is named `FuzzReadMongoMessage` (it was planned as `FuzzParseMongoMessage`), after `readMongoMessage`.
