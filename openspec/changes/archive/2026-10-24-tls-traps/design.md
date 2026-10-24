## Context

The `https` trap must reuse the HTTP request handling of `http-request-capture` and add TLS plus ClientHello fingerprints.

## Decisions

- **Shared handler.** `HTTPTrap` is built by `newHTTPTrap(proto, ...)`. `HTTPSTrap` embeds it and only sets a `wrap` hook that puts a TLS listener in front of the PROXY-aware listener. Sessions stay keyed by the accepted `net.Conn` (`ConnContext`/`ConnState`); `Stop(ctx)` is `http.Server.Close`, which also closes connections still in the handshake.
- **Handshake timeout.** `http.Server` handshakes `*tls.Conn` under `ReadTimeout`/`WriteTimeout`, which are the session timeout of `https`. A client that sends nothing is closed after that time.
- **Certificate.** One PEM file (certificate and PKCS#8 key) at `RAN_HTTPS_CERT_PATH`, ECDSA P-256, `CN=localhost`, 10 years. Missing, unreadable, invalid or expired files are replaced; if the replacement cannot be written, an ephemeral certificate is used and a warning is logged.
- **ClientHello capture.** `tls.ClientHelloInfo` has no extension order and no raw GREASE-free extension list, so JA3/JA4 cannot be computed exactly from it. A small `helloConn` wrapper therefore records the first TLS record the client sends (at most 16389 bytes) and `parseClientHello` reads it. `GetConfigForClient` runs after the full hello was read and before version and cipher negotiation, so hellos that fail the handshake are fingerprinted too. The SNI comes from `ClientHelloInfo.ServerName` and falls back to the parsed one.
- **Bounds.** 256 cipher suites, 128 extensions, 64 groups, 16 point formats, 128 signature algorithms, 32 versions, 16 ALPN entries; SNI and ALPN pass through `sanitizeHTTPValue` (control characters replaced, 256 bytes). The parser is a bounds-checked cursor and never allocates from a length field.
- **JA3** follows the original definition (legacy version, ciphers, extensions, groups, point formats; GREASE removed; MD5). **JA4** is the TCP flavour (`t`), with sorted ciphers and sorted extensions (SNI and ALPN excluded) plus signature algorithms in wire order, each hashed to 12 hex characters of SHA-256.

## Limitations

- Only a ClientHello that fits into the first TLS record is fingerprinted. A hello fragmented over several records is still handled by `crypto/tls` but gets no JA3/JA4 (SNI is still logged).
- Counts and lists are capped, so a hostile hello with more than the caps differs from the exact JA3/JA4 of the full hello.
- A failed handshake ends as a `probe` session with the default outcome; Go gives no per-connection handshake error to the trap, so no separate outcome label is set.
- Go's default TLS versions and cipher suites apply (TLS 1.2 minimum for servers); older clients fail the handshake but are still fingerprinted.
