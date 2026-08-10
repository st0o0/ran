## Why

ran is a new Go honeypot container with no CI/CD infrastructure yet. The eir and bifrost repos already have a battle-tested, identical workflow pattern for Go container projects (CI, release-please, dev-builds, security scanning, conventional commits). Adopting it gives ran production-grade automation from day one instead of reinventing it.

## What Changes

- Add 5 GitHub Actions workflows: `ci.yml`, `release.yml`, `commitlint.yml`, `dev-build.yml`, `security.yml`
- Add release-please configuration (simple release type, starting at `0.0.0`)
- Add commitlint configuration enforcing conventional commits
- Add Dependabot configuration for gomod, github-actions, and docker ecosystems
- Add golangci-lint and hadolint configuration
- Add PR template, issue templates, contributing guide, security policy, and code of conduct
- Add `.github/` environment configuration references (dev environment for dev-build gating)

## Capabilities

### New Capabilities
- `ci-pipeline`: PR-triggered CI with unit tests, linting (Go + Dockerfile), Docker build + smoke test, and e2e tests as branch-protection required checks
- `release-automation`: Automated versioning, changelog generation, GitHub Releases, multi-arch Docker image publishing (amd64 + arm64) to GHCR with cosign signing and SLSA/SBOM attestations
- `dev-builds`: Label-gated preview image publishing from PRs with environment approval
- `security-scanning`: Trivy vulnerability scanning on dependency changes + weekly schedule, reporting to GitHub Security tab
- `commit-conventions`: Conventional commit enforcement via commitlint
- `dependency-management`: Dependabot weekly updates for Go modules, GitHub Actions, and Docker base images

### Modified Capabilities

_(none — greenfield repo)_

## Impact

- New files in `.github/workflows/`, `.github/` templates, and repo root config files
- Requires GitHub environment `dev` to be created for dev-build approval gating
- Requires repository settings: branch protection on `main` with required checks (unit, lint, build, e2e, commitlint)
- GHCR package `ghcr.io/st0o0/ran` will be created on first release
