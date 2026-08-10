## Purpose

Conventional commit enforcement via commitlint on all pull requests.

## Requirements

### Requirement: Conventional commit enforcement
All PR commits SHALL follow Conventional Commits format, enforced by commitlint via `wagoid/commitlint-github-action@v6`.

#### Scenario: Valid commit
- **WHEN** a PR has commits like `feat: add honeypot listener`
- **THEN** the commitlint check passes

#### Scenario: Invalid commit
- **WHEN** a PR has commits like `added stuff`
- **THEN** the commitlint check fails

### Requirement: Allowed commit types
The commitlint config SHALL allow: feat, fix, perf, docs, chore, refactor, style, test, ci, build, deps.

#### Scenario: deps type allowed
- **WHEN** Dependabot creates a commit like `deps: bump golang.org/x/net`
- **THEN** the commitlint check passes

### Requirement: Relaxed style rules
Header max length SHALL be 120 (warning only). Body/footer line length and subject case rules SHALL be disabled.

#### Scenario: Long header
- **WHEN** a commit header is 100 characters
- **THEN** commitlint does not reject (warning at most)

### Requirement: Dependabot commit bypass
Commits from `dependabot[bot]` SHALL be ignored by commitlint.

#### Scenario: Dependabot commit
- **WHEN** Dependabot creates a commit
- **THEN** commitlint skips validation for that commit
