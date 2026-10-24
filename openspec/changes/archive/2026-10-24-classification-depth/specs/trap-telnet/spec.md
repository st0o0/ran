## ADDED Requirements

### Requirement: Option negotiation
The Telnet trap SHALL parse IAC sequences in the input, answer `DO` with `WONT` and `WILL` with `DONT`, and SHALL NOT pass IAC bytes into the username or password.

#### Scenario: Mirai-style client
- **WHEN** a client sends `FF FB 18` followed by `root\r\n`
- **THEN** the username is `root` and a `DONT` reply for the option was sent

#### Scenario: Truncated sequence
- **WHEN** the input ends inside an IAC sequence
- **THEN** the sequence is dropped and the session ends normally

#### Scenario: Subnegotiation containing a newline
- **WHEN** a subnegotiation contains `0x0A` before its `IAC SE`
- **THEN** the line reader cuts it there: the unterminated start is dropped, the remainder is the next line (a stray `IAC SE` is dropped), and no terminal type is logged

#### Scenario: Reply bound
- **WHEN** a line carries more options than fit in 192 bytes of replies
- **THEN** the surplus options are dropped without an answer

### Requirement: Terminal type
If a client reports a terminal type via subnegotiation, the trap SHALL log it bounded to 64 bytes.

#### Scenario: TTYPE reply
- **WHEN** a client sends `IAC SB TTYPE IS xterm IAC SE`
- **THEN** `xterm` is logged as the terminal type
