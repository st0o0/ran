## ADDED Requirements

### Requirement: Generated settings register
The repository SHALL contain `docs/data/settings.generated.json`, generated from `config.Settings`, listing every configuration variable with name, kind, default, group and summary. A test SHALL fail when the register, the variables read by `config.Load`, their defaults, or the generated file disagree.

#### Scenario: New variable without register entry
- **WHEN** `Load` reads a variable that is not in the register
- **THEN** the drift test fails and names the variable

#### Scenario: Stale generated file
- **WHEN** the register changes and the JSON is not regenerated
- **THEN** the generated-file test fails

### Requirement: Scenario based builder page
The documentation site SHALL provide a builder page that starts from a deployment scenario, lets the user enable traps and adjust settings, and exports only values that differ from the default as an env file, a Compose file and a `docker run` line.

#### Scenario: Reverse proxy scenario
- **WHEN** the user picks the reverse proxy scenario and the HTTP trap
- **THEN** the output sets `RAN_PROXY_PROTOCOL` to the chosen traps and `RAN_PROXY_TRUSTED`, and a Caddy `proxy_protocol v2` hint is shown

#### Scenario: Defaults are omitted
- **WHEN** a setting equals its default
- **THEN** it does not appear in the export

### Requirement: Warnings match the sensor
The builder SHALL show a warning or error for every rule in the shared case vectors, and the Go configuration loader SHALL produce the same outcome for the same input.

#### Scenario: UDP trap in the PROXY list
- **WHEN** a UDP trap is selected for PROXY protocol
- **THEN** the builder shows an error and `config.Load` rejects the same environment

### Requirement: Share and import without a server
The builder SHALL keep its state in the URL hash, SHALL restore it on load without throwing on malformed input, SHALL import an existing env file, and SHALL NOT transmit or store the configuration.

#### Scenario: Round trip
- **WHEN** a configuration is encoded into the hash and decoded again
- **THEN** the resulting configuration equals the original

#### Scenario: Broken hash
- **WHEN** the hash is not valid
- **THEN** the page loads with defaults

### Requirement: No secrets
The builder SHALL NOT ask for the CrowdSec password and SHALL write a visible placeholder instead.

#### Scenario: CrowdSec enabled
- **WHEN** CrowdSec is enabled in the builder
- **THEN** the export contains `CHANGE_ME` for the password and a note to replace it
