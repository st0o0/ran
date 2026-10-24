## ADDED Requirements

### Requirement: Docker, Kubernetes and MongoDB traps
`docker`, `kubernetes` and `mongodb` SHALL be valid trap names with default ports `:2375`, `:6443` and `:27017`, registered in `DefaultPorts`, `ValidTraps` and `Registry`.

#### Scenario: Enable the new traps
- **WHEN** `RAN_TRAPS=docker,kubernetes,mongodb` is set
- **THEN** all three traps start on their default ports and appear in `/healthz`

### Requirement: Telnet default addresses
The default listen addresses of `telnet` SHALL be `:23,:2323`.

#### Scenario: Default telnet
- **WHEN** `RAN_TRAPS=telnet` is set without `RAN_TELNET_ADDR`
- **THEN** the trap listens on `:23` and `:2323`
