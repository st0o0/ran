## ADDED Requirements

### Requirement: Docker Engine API stub
The `docker` trap SHALL answer `GET /_ping`, `/version`, `/info`, `/containers/json` and `/images/json` (also with a `/v<major>.<minor>` prefix) with plausible static answers. It SHALL reuse the request handling of the `http` trap: one session per connection, a request body read up to 16 KiB, and keep-alive connections closed by `Stop(ctx)`.

#### Scenario: Version probe
- **WHEN** a client requests `GET /version`
- **THEN** a JSON document with an API version and OS fields is returned with HTTP 200 and the session stays a `probe`

### Requirement: Container creation is an attack
A `POST /containers/create` or `POST /containers/{id}/exec` request SHALL be recorded as a command with image and command line (alert meta `command`, bounded to 256 bytes, the image name cut to 64 bytes so the command line always fits) and answered with `403` and an error message. Any other method except `GET`, `HEAD` and `OPTIONS` SHALL be recorded as `METHOD /path` and refused: `POST`, `PUT`, `PATCH` and `DELETE` change state, and `PROPFIND`, `CONNECT`, `TRACE` and unknown methods are not part of the Docker API. `OPTIONS` is read-only (crawlers and CORS preflights send it) and stays a probe. Nothing SHALL be executed or pulled.

#### Scenario: Miner deployment attempt
- **WHEN** a client posts a create request for image `alpine` with a `wget` command
- **THEN** a command is logged with image and command, an alert is raised, the session is `attack` and the response is an error

#### Scenario: Unparsable body
- **WHEN** a create request carries a body that is not valid JSON
- **THEN** the request is still recorded as a command (without image and command line) and refused

### Requirement: Bounded input
Every read SHALL be bounded and unknown paths SHALL return `404` without storing the path beyond the 256 byte logging bound. Request headers and bodies SHALL NOT be copied into alert meta; the alert IP SHALL be the socket peer.

#### Scenario: Oversized body
- **WHEN** a client sends a body larger than 16 KiB
- **THEN** the read stops at the limit and memory stays bounded

#### Scenario: Forged forwarding headers
- **WHEN** a request carries `X-Forwarded-For: 8.8.8.8`
- **THEN** the address is logged as `claimed_client_ip` only and the alert uses the socket peer
