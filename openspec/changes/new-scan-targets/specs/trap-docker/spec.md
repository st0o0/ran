## ADDED Requirements

### Requirement: Docker Engine API stub
The `docker` trap SHALL answer `GET /_ping`, `/version`, `/info`, `/containers/json` and `/images/json` with plausible static JSON. Requests with a body SHALL be read up to 16 KiB.

#### Scenario: Version probe
- **WHEN** a client requests `GET /version`
- **THEN** a JSON document with an API version and OS fields is returned with HTTP 200 and the session stays a `probe`

### Requirement: Container creation is an attack
A `POST /containers/create` or `POST /containers/{id}/exec` request SHALL be recorded as a command with image and command line (bounded to 256 bytes) and answered with an error. Nothing SHALL be executed or pulled.

#### Scenario: Miner deployment attempt
- **WHEN** a client posts a create request for image `alpine` with a `wget` command
- **THEN** a command is logged with image and command, an alert is raised, the session is `attack` and the response is an error

### Requirement: Bounded input
Every read SHALL be bounded and unknown paths SHALL return `404` without storing the path beyond the logging bound.

#### Scenario: Oversized body
- **WHEN** a client sends a body larger than 16 KiB
- **THEN** the read stops at the limit and memory stays bounded
