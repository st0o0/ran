# trap-banner Specification

## Purpose
TBD - created by archiving change catch-all-and-banner-trap. Update Purpose after archive.
## Requirements
### Requirement: Configured banner services
The `banner` trap SHALL read `RAN_BANNER_SERVICES`, a comma-separated list of `port=name:banner` entries (at most 10), validate it at startup and listen on each port. Ports SHALL be unique and between 1 and 65535, the name SHALL use only `a-z`, `0-9`, `_` and `-` (at most 32 bytes), and the decoded banner SHALL be 1 to 256 bytes. The banner SHALL be sent on connect with the escapes `\r`, `\n`, `\t`, `\` and `\,` interpreted; any other escape SHALL be an error. A service SHALL send its own banner, chosen by the listener and not by any address supplied by the client.

#### Scenario: Valid service
- **WHEN** `RAN_BANNER_SERVICES=9999=custom:hello\r\n`
- **THEN** the trap listens on `:9999` and sends `hello\r\n` on connect

#### Scenario: Two services
- **WHEN** two entries use different ports and banners
- **THEN** each port sends only its own banner

#### Scenario: Invalid entry
- **WHEN** an entry has no port, a bad name, a bad escape, an empty or oversized banner, or a duplicate port, or more than 10 entries are given
- **THEN** `ran check-config` exits 1 and names `RAN_BANNER_SERVICES` and the offending entry

### Requirement: Client input logging
Data sent by the client SHALL be read as lines up to 512 bytes (at most 100 lines per connection), sanitized, logged as commands with the service name and counted as `attack`. A final line without newline SHALL be logged too. A line over 512 bytes SHALL be logged as a payload and end the session with outcome `too_long`. A connect without data SHALL be a `probe`. The metrics protocol label SHALL be the fixed `banner`; the service name SHALL only appear in logs and alert meta.

#### Scenario: Command line
- **WHEN** a client sends `STAT\r\n`
- **THEN** a command `STAT` is logged and the session is `attack`

#### Scenario: No data
- **WHEN** a client connects, reads the banner and disconnects
- **THEN** the session is a `probe`

