## Purpose

Memcached honeypot trap that simulates a Memcached server to capture unauthorized command attempts via the text protocol.

## Requirements

### Requirement: Memcached command capture
The Memcached trap SHALL listen on TCP, accept text-protocol commands, log them, and respond with errors.

#### Scenario: Stats command
- **WHEN** a client sends `stats\r\n`
- **THEN** the trap SHALL log a command event with command="stats" and respond with `ERROR\r\n`

#### Scenario: Get/set command logging
- **WHEN** a client sends `get key1` or `set key1 0 0 5\r\nvalue\r\n`
- **THEN** the trap SHALL log the command and key, and respond with `ERROR\r\n`
