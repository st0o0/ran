## ADDED Requirements

### Requirement: Catch-all and banner traps
`catchall` and `banner` SHALL be valid trap names without a default port. Enabling either without its address variable (`RAN_CATCHALL_ADDR`, `RAN_BANNER_SERVICES`) SHALL make the configuration invalid with a message naming the variable.

#### Scenario: Missing address
- **WHEN** `RAN_TRAPS=catchall` is set without `RAN_CATCHALL_ADDR`
- **THEN** `ran check-config` exits 1 and names `RAN_CATCHALL_ADDR`
