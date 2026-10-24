## ADDED Requirements

### Requirement: HTTPS trap registration
The system SHALL accept `https` as a trap name in `RAN_TRAPS` with the default listen address `:8443`, overridable (also with several comma-separated addresses) through `RAN_HTTPS_ADDR`. `RAN_HTTPS_CERT_PATH` (default `/data/https_cert.pem`) SHALL name the certificate file of the trap. `config.DefaultPorts`, `config.ValidTraps` and `trap.Registry` SHALL all contain `https`.

#### Scenario: Default address
- **WHEN** `RAN_TRAPS=https` is set and `RAN_HTTPS_ADDR` is not
- **THEN** `TrapAddr("https")` returns `:8443`

#### Scenario: Certificate path
- **WHEN** `RAN_HTTPS_CERT_PATH` is not set
- **THEN** the certificate path is `/data/https_cert.pem`
