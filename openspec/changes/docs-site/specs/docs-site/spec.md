## ADDED Requirements

### Requirement: Documentation site
The repository SHALL contain a VitePress site under `docs/` with a pinned lockfile that builds without errors and without dead links, and a workflow SHALL deploy it to GitHub Pages after a release.

#### Scenario: Pull request build
- **WHEN** a pull request changes files under `docs/`
- **THEN** CI builds the site with a frozen lockfile and fails on build errors or dead links

#### Scenario: Release deploy
- **WHEN** release-please creates a release
- **THEN** the docs job deploys `docs/.vitepress/dist` to GitHub Pages

### Requirement: Generated trap table
The trap table SHALL be generated from `config.DefaultPorts` and `config.AddresslessTraps`, and a test SHALL fail when the committed file differs from the generator output.

#### Scenario: New trap
- **WHEN** a trap is added to `DefaultPorts` without regenerating the table
- **THEN** the drift test fails

### Requirement: Documented variables stay checked
The config contract test SHALL treat the README and all Markdown pages under `docs/` as the documentation, and SHALL fail when a `RAN_*` variable is missing from all of them or when they reference an unknown variable.

#### Scenario: Variable moved to the site
- **WHEN** a variable is documented only on a site page
- **THEN** the contract test passes

#### Scenario: Undocumented variable
- **WHEN** a config variable appears in neither README nor site
- **THEN** the contract test fails
