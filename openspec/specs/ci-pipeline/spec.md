## Purpose

PR-triggered CI pipeline with unit tests, linting, Docker build, and e2e tests as branch-protection required checks.

## Requirements

### Requirement: PR-triggered CI pipeline
The CI pipeline SHALL run on all pull requests with no path filter. It SHALL NOT run on push to main (release.yml owns main).

#### Scenario: PR opened
- **WHEN** a pull request is opened or updated
- **THEN** all four CI jobs (unit, lint, build, e2e) run on the merge-result commit

#### Scenario: Concurrent pushes
- **WHEN** a new commit is pushed to a PR while CI is running
- **THEN** the superseded run is cancelled (concurrency group `ci-${{ github.ref }}`)

### Requirement: Unit test job
The `unit` job SHALL run `go test -race ./...` with a 10-minute timeout.

#### Scenario: Tests pass
- **WHEN** all Go tests pass with the race detector enabled
- **THEN** the unit job succeeds

### Requirement: Lint job
The `lint` job SHALL run golangci-lint v2 and hadolint on the Dockerfile with a 10-minute timeout.

#### Scenario: Clean lint
- **WHEN** Go code passes golangci-lint and the Dockerfile passes hadolint
- **THEN** the lint job succeeds

### Requirement: Build job
The `build` job SHALL build the Docker image with BuildX and GHA caching, then run a smoke test with a 15-minute timeout.

#### Scenario: Smoke test
- **WHEN** the image is built and run without configuration
- **THEN** the container exits with code 1 (missing config)

### Requirement: E2E job
The `e2e` job SHALL depend on unit, lint, and build. It SHALL rebuild the image (cache hit) and execute `tests/e2e/run.sh` with a 15-minute timeout.

#### Scenario: E2E after prerequisites pass
- **WHEN** unit, lint, and build jobs all succeed
- **THEN** the e2e job runs `tests/e2e/run.sh`

### Requirement: Required checks for branch protection
The four CI jobs SHALL be named `unit`, `lint`, `build`, `e2e` to match branch-protection required check names.

#### Scenario: Branch protection alignment
- **WHEN** branch protection is configured on main with required checks
- **THEN** the job names match exactly: unit, lint, build, e2e
