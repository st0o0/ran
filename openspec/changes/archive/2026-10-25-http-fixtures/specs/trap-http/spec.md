## ADDED Requirements

### Requirement: Static fixtures
The `http` and `https` traps SHALL answer `GET` and `HEAD` requests whose exact path matches a built-in fixture with the fixture status, headers and body. Fixture bodies SHALL be static and SHALL NOT include any part of the request. Logging and classification SHALL run before the fixture is chosen and SHALL NOT change. The `docker`, `kubernetes` and `mcp` traps SHALL NOT use fixtures.

#### Scenario: Git metadata
- **WHEN** a client requests `GET /.git/HEAD`
- **THEN** a response with `ref: refs/heads/main` and HTTP 200 is returned and the request is recorded by the request capture rules

#### Scenario: No reflection
- **WHEN** the path contains `<script>`, or the query, a header, a cookie or the Authorization header carries a marker string
- **THEN** no response header or body contains the path or the marker

#### Scenario: Classification unchanged
- **WHEN** a client requests `GET /.env` or `GET /robots.txt`
- **THEN** `/.env` is recorded as a command and classifies as `attack`, and `/robots.txt` stays a `probe`

#### Scenario: HEAD
- **WHEN** a client sends `HEAD /robots.txt`
- **THEN** the status and headers of the `GET` answer are returned, `Content-Length` is the body length of the `GET` answer and no body is sent

#### Scenario: Other methods
- **WHEN** a client sends `POST`, `PUT` or `OPTIONS` to a fixture path
- **THEN** the existing behavior applies, including credential capture and the login error page for a form `POST`

#### Scenario: Other HTTP traps
- **WHEN** a client requests a fixture path on `docker`, `kubernetes` or `mcp`
- **THEN** that trap answers as before and no fixture is served

### Requirement: Operator fixtures
`RAN_HTTP_FIXTURES` SHALL name a JSON file `{"fixtures":[{"path","status","headers","body"}]}` with at least 1 and at most 64 entries, bodies of at most 8 KiB, a file size of at most 1 MiB, unique paths that start with `/` and contain no `%`, statuses from `200 204 400 401 403 404 500 503` and headers from a fixed allow-list. Unknown fields and duplicate JSON keys SHALL be rejected. The file SHALL be read once at startup when `http` or `https` is enabled, and an invalid file SHALL make the configuration invalid with the offending entry named. Operator fixtures SHALL take precedence over built-in fixtures with the same path and SHALL NOT apply to methods other than `GET` and `HEAD`.

#### Scenario: Valid file
- **WHEN** the file defines `/status` with status 200 and a body
- **THEN** requests to `/status` receive that response on `http` and `https`

#### Scenario: Oversized body
- **WHEN** an entry body exceeds 8 KiB
- **THEN** `ran check-config` exits 1 and names the entry

#### Scenario: Invalid entry
- **WHEN** the file has no entries (an empty `fixtures` list), more than 64 entries, a duplicate path, a path without a leading `/` or with a `%`, a duplicate JSON key, a status outside the allowed set, a header outside the allow-list, an unknown field, invalid JSON or a size over 1 MiB, or cannot be read
- **THEN** `ran check-config` exits 1 and the error names `RAN_HTTP_FIXTURES` and, for entry errors, the entry

#### Scenario: Operator overrides built-in
- **WHEN** the file defines `/robots.txt`
- **THEN** `GET /robots.txt` returns the operator response
