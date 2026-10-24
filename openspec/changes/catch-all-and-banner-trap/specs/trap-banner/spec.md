## ADDED Requirements

### Requirement: Configured banner services
The `banner` trap SHALL read `RAN_BANNER_SERVICES`, a comma-separated list of `port=name:banner` entries (at most 10), validate it at startup and listen on each port. The banner SHALL be sent on connect with escapes `\r` and `\n` interpreted.

#### Scenario: Valid service
- **WHEN** `RAN_BANNER_SERVICES=9999=custom:hello\r\n`
- **THEN** the trap listens on `:9999` and sends `hello\r\n` on connect

#### Scenario: Invalid entry
- **WHEN** an entry has no port or more than 10 entries are given
- **THEN** `ran check-config` exits 1 and names the entry

### Requirement: Client input logging
Data sent by the client SHALL be read as lines up to 512 bytes, logged as commands and counted as `attack`. A connect without data SHALL be a `probe`.

#### Scenario: Command line
- **WHEN** a client sends `STAT\r\n`
- **THEN** a command `STAT` is logged and the session is `attack`
