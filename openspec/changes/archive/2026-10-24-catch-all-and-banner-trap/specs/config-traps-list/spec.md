## ADDED Requirements

### Requirement: Catch-all and banner traps
`catchall` and `banner` SHALL be valid trap names without a default port; they are listed in `config.AddresslessTraps` together with the variable they require, and are not part of `config.DefaultPorts`. Enabling either without its address variable (`RAN_CATCHALL_ADDR`, `RAN_BANNER_SERVICES`) SHALL make the configuration invalid with a message naming the variable. The variables SHALL be read only when the trap is enabled.

#### Scenario: Missing address
- **WHEN** `RAN_TRAPS=catchall` is set without `RAN_CATCHALL_ADDR`
- **THEN** `ran check-config` exits 1 and names `RAN_CATCHALL_ADDR`

#### Scenario: Missing services
- **WHEN** `RAN_TRAPS=banner` is set without `RAN_BANNER_SERVICES`
- **THEN** `ran check-config` exits 1 and names `RAN_BANNER_SERVICES`

#### Scenario: Registry agreement
- **WHEN** the tests compare `DefaultPorts`, `AddresslessTraps`, `ValidTraps` and `trap.Registry`
- **THEN** the first two are disjoint and their union equals the other two
