## ADDED Requirements

### Requirement: Static fixtures
The HTTP trap SHALL answer requests whose path matches a built-in fixture with the fixture status, headers and body. Fixture bodies SHALL be static and SHALL NOT include any part of the request.

#### Scenario: Git metadata
- **WHEN** a client requests `GET /.git/HEAD`
- **THEN** a response with `ref: refs/heads/main` and HTTP 200 is returned and the request is recorded by the request capture rules

#### Scenario: No reflection
- **WHEN** the path contains `<script>`
- **THEN** the response body does not contain the path

### Requirement: Operator fixtures
`RAN_HTTP_FIXTURES` SHALL name a file with at most 64 entries and bodies of at most 8 KiB. The file SHALL be read once at startup and an invalid file SHALL make the configuration invalid with the offending entry named.

#### Scenario: Valid file
- **WHEN** the file defines `/status` with status 200 and a body
- **THEN** requests to `/status` receive that response

#### Scenario: Oversized body
- **WHEN** an entry body exceeds 8 KiB
- **THEN** `ran check-config` exits 1 and names the entry
