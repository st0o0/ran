## Context

ran is a new Go honeypot container (`ghcr.io/st0o0/ran`). The repo currently has only a README and LICENSE. The eir and bifrost repos share an identical, proven CI/CD pattern for Go container projects. This change adopts that pattern verbatim for ran, with only the project-specific values swapped (image name, description, smoke test, arch targets).

## Goals / Non-Goals

**Goals:**
- Fully automated release pipeline from conventional commit to signed multi-arch container image
- PR validation with unit tests, linting, Docker build, and e2e tests as required checks
- Weekly vulnerability scanning with GitHub Security tab integration
- Label-gated dev-build previews from PRs
- Community contribution infrastructure (templates, guidelines, policies)

**Non-Goals:**
- Custom workflow logic beyond what eir/bifrost already use
- Helm charts, Terraform modules, or deployment automation
- Go module publishing (ran is a binary, not a library)

## Decisions

### 1. Copy from bifrost, not eir
bifrost is the more recent repo with newer action versions and the same arch targets (amd64 + arm64, no arm/v7). Using it as the source minimizes diff.

### 2. Architecture targets: amd64 + arm64 only
Matches bifrost. No arm/v7 needed for a honeypot deployment.

### 3. Initial version 0.0.0
The `.release-please-manifest.json` starts at `0.0.0`. The first release-please cycle will create `0.1.0` when feat commits land.

### 4. Smoke test placeholder
The ci.yml smoke test needs a ran-specific command. Since the binary doesn't exist yet, the smoke test will run `ran` without arguments and expect exit code 1 (the standard "missing config" pattern from eir/bifrost). This will be adjusted when the binary is implemented.

### 5. golangci-lint config: clean slate
bifrost's `.golangci.yml` has project-specific rule suppressions (SA4000, ST1005). ran starts with only the base presets — no project-specific exclusions until they're needed.

### 6. Hadolint config: identical
Same `failure-threshold: warning` with DL3018 ignored (apk version pinning not required for scratch-based images).

## Risks / Trade-offs

- **Workflows exist before code** — CI will fail until the Go module, Dockerfile, and test structure are in place. This is intentional: the infrastructure is ready when the code arrives, and the PR that adds the initial code will validate against it.
- **Smoke test is a placeholder** — needs to be updated when the ran binary interface is defined.
- **e2e test script is referenced but doesn't exist** — the e2e CI job will fail until `tests/e2e/run.sh` is created. This is acceptable because e2e is a required check, so it naturally blocks merging until the test exists.

## Open Questions

_(none — this is a well-understood pattern transfer)_
