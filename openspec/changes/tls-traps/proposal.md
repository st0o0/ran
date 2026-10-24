## Why

rán has no TLS anywhere. A large share of internet scanning goes to `443`, `8443`, `993`, `465` and similar ports. A TLS ClientHello hitting a plaintext trap fails the handshake and is logged as a probe at best, and the TLS fingerprint (SNI, JA3/JA4) is lost. qeeqbox/honeypots, Dionaea, Heralding and T-Pot all cover TLS.

## What Changes

- New trap `https` (default `:8443`) that wraps the existing HTTP handler in `crypto/tls`. A self-signed certificate is generated at first start and persisted next to the SSH host key (`RAN_HTTPS_CERT_PATH`, default `/data/https_cert.pem`), with an ephemeral fallback like the SSH key.
- The ClientHello is captured via `GetConfigForClient`: SNI, offered versions, cipher suites, extensions, curves and point formats are hashed to JA3 and JA4 and logged. Lists are bounded and the hashes are the only derived values in alert meta (`sni`, `ja3`, `ja4`).
- A completed TLS handshake without an HTTP request stays a probe. Requests inside TLS follow the rules of `http-request-capture`.
- Registered in `config.DefaultPorts`, `config.ValidTraps` and `trap.Registry` (contract tests), multi-port via `RAN_HTTPS_ADDR`.

## Capabilities

### New Capabilities

- `trap-https`: TLS-terminating HTTP trap with ClientHello fingerprinting.

### Modified Capabilities

- `config-traps-list`: `https` added to the trap list and default ports.

## Impact

- New `internal/trap/https.go` and `tlsfp.go`; `config.go`, `registry.go`; README trap table and `RAN_HTTPS_*` rows (contract test); Dockerfile `EXPOSE` if listed.
- Depends on `http-request-capture` (shares the handler).

## Non-goals

- No mTLS, no client certificate handling, no certificate that imitates a real host.
- No STARTTLS or TLS on other protocols in this change (SMTPS, IMAPS, LDAPS come later).
- No TLS version or cipher hardening beyond the Go defaults: the trap should accept old clients.
