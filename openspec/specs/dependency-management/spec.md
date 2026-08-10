## Purpose

Automated dependency updates via Dependabot for Go modules, GitHub Actions, and Docker base images.

## Requirements

### Requirement: Dependabot configuration
Dependabot SHALL monitor three ecosystems weekly: gomod, github-actions, and docker.

#### Scenario: Go dependency update
- **WHEN** a new version of a Go dependency is available
- **THEN** Dependabot creates a grouped PR with `deps` commit prefix

#### Scenario: GitHub Actions update
- **WHEN** a new version of a GitHub Action is available
- **THEN** Dependabot creates a grouped PR with `deps` commit prefix

#### Scenario: Docker base image update
- **WHEN** a new version of the Docker base image is available
- **THEN** Dependabot creates a PR with `deps` commit prefix

### Requirement: Dependency grouping
Go dependencies SHALL be grouped as `go-all` and GitHub Actions as `actions-all`, so each ecosystem produces at most one PR per week.

#### Scenario: Multiple Go updates
- **WHEN** three Go dependencies have updates in the same week
- **THEN** Dependabot creates a single PR updating all three
