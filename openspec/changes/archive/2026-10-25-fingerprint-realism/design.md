## Context

Every instance used to present the same version strings. `fingerprint-realism` lets an instance pick plausible values from small built-in sets, stable per instance, without changing protocol behavior.

## Decisions

**Package and profile.** `internal/fingerprint` holds the tables, `Fixed()`, `FromSeed(seed)` and `Load(mode, path, logger)`. A `Profile` is a plain value: `SSH` (full identification string), `MySQL`, `HTTP{Server, PHP, StatusServer}`, `SMTP{Host, Software}`, `Elasticsearch{Version, ClusterName, NodeName}`. `config.Config.Fingerprint(logger)` resolves it once (`sync.Once` in a pointer field created by `Load`), so every trap of the process shares one object even when the seed is ephemeral. `Load` of the config does not touch the seed file (`ran check-config` has no side effects); the first trap constructor does. A `Config` literal without a profile (tests) is fixed mode. `SetFingerprint` injects a profile in tests.

**Selection.** `index = uint64(HMAC-SHA256(seed, "ran/fingerprint/v1/" + label)[:8]) mod len(table)`, with one label per table (`ssh`, `mysql`, `http`, `smtp/host`, `smtp/software`, `elasticsearch/version`, `elasticsearch/cluster`). Labels are independent, so adding a table later does not move the other choices.

**Why a seed and not random per start.** A random pick per start would change the banners on every restart, which is itself a tell and breaks clients that pin them. A seed persisted next to the SSH host key gives the same stability as the host key. Never random per connection.

**Consistency rules.** An entry is internally consistent: an Apache entry carries the Apache build, the PHP version of the same distribution release and a matching `/server-status` line; an nginx entry has no `StatusServer`, so the `/server-status` fixture is not served (the path falls back to the login page) and `phpinfo` reports `FPM/FastCGI`. The Elasticsearch cluster and node name are one pair, and `/` and `/_cluster/health` use the same cluster name. SMTP hosts come only from the documentation domains (`example.com`, `example.net`, `example.org`). Traps choose independently of each other; the only shared thing is the profile object. The HTTP profile is read in `handleRequest` (headers) and `builtinHTTPFixtures(profile.HTTP)` (bodies), so `http`, `https` and the fixtures cannot disagree. Operator fixtures still override headers.

**Persistence.** The seed file holds 64 hex characters plus a newline. A missing, unreadable, corrupt or short file is replaced by a new seed, written to a temporary file next to the target (mode `0600`, fsync) and renamed over it, like the https certificates. An unwritable location, or a path that is a directory, gives an ephemeral seed and a warning; startup never fails.

**`kind` vocabulary.** Fixed strings, one set per trap, never client data: `vnc` `auth_response`; `rdp` `connection_request`; `oracle` `connect`; `mqtt` `connect`; `modbus` `write`, `unknown_function`; `minecraft` `status`, `login`, `handshake`; `adb` `connect`, `auth`, `shell_command`. One extra key stays far below the 32 key cap of the CrowdSec sink next to the six sensor keys.

## Non-goals

No claim to defeat fingerprinting; no per-connection randomness; no protocol behavior change. FTP, POP3, IMAP, Redis and other banners are not varied in this change.
