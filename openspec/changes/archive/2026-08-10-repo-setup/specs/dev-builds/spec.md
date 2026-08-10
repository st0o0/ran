## ADDED Requirements

### Requirement: Label-gated dev image publishing
The dev-build workflow SHALL run on PRs with the `dev-build` label, gated by the `dev` environment (requires reviewer approval). Fork PRs SHALL be skipped.

#### Scenario: PR with dev-build label
- **WHEN** a PR has the `dev-build` label and is not from a fork
- **THEN** after environment approval, a dev image is built and pushed to GHCR

#### Scenario: Fork PR with label
- **WHEN** a fork PR has the `dev-build` label
- **THEN** the workflow is skipped (GITHUB_TOKEN cannot push to GHCR)

### Requirement: Dev image tagging
Dev images SHALL be tagged with `pr-<number>` and `dev-<short-sha>`. The VERSION build arg SHALL be `pr-<number>-<shortsha>`.

#### Scenario: Dev image tags
- **WHEN** PR #42 at SHA abc1234 triggers a dev build
- **THEN** tags `ghcr.io/st0o0/ran:pr-42` and `ghcr.io/st0o0/ran:dev-abc1234` are pushed

### Requirement: Dev build uses PR branch head
The checkout SHALL use the PR branch head SHA, not the merge commit, so the `dev-<sha>` tag matches the actual commit.

#### Scenario: SHA alignment
- **WHEN** a dev build runs
- **THEN** the checked-out code matches `github.event.pull_request.head.sha`

### Requirement: PR comment with pull command
After pushing, the workflow SHALL post or update a comment on the PR with the `docker pull` command.

#### Scenario: Comment posted
- **WHEN** a dev image is pushed for the first time on a PR
- **THEN** a comment with the `docker pull` command is created

#### Scenario: Comment updated
- **WHEN** a new dev image is pushed for the same PR
- **THEN** the existing comment is updated instead of creating a duplicate

### Requirement: Dev build concurrency
A new push SHALL cancel a still-pending dev-build for the same PR.

#### Scenario: Superseded dev build
- **WHEN** a new commit is pushed to a PR while a dev-build approval is pending
- **THEN** the pending run is cancelled
