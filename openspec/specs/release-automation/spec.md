## Purpose

Automated versioning, changelog generation, GitHub Releases, and multi-arch Docker image publishing to GHCR with supply chain security (cosign signing, SLSA provenance, SBOM attestations).

## Requirements

### Requirement: Release-please integration
The release workflow SHALL use `googleapis/release-please-action@v5` with `release-type: simple`, triggered on push to main. The initial manifest version SHALL be `0.0.0`.

#### Scenario: Feature commit merged
- **WHEN** a `feat:` commit is merged to main
- **THEN** release-please creates or updates a Release PR bumping the minor version and updating CHANGELOG.md

#### Scenario: Fix commit merged
- **WHEN** a `fix:` commit is merged to main
- **THEN** release-please creates or updates a Release PR bumping the patch version

#### Scenario: Release PR merged
- **WHEN** the Release PR is merged
- **THEN** release-please creates a GitHub Release with a git tag (e.g. `v0.1.0`)

### Requirement: Multi-arch Docker image publishing
When a release is created, the workflow SHALL build and push a multi-arch Docker image to `ghcr.io/st0o0/ran` for `linux/amd64` and `linux/arm64`.

#### Scenario: Release image tags
- **WHEN** version 0.1.0 is released
- **THEN** three tags are pushed: `0.1.0`, `0.1`, and `latest`

#### Scenario: Version build arg
- **WHEN** the Docker image is built for release
- **THEN** the `VERSION` build arg is set to the release version

### Requirement: Image signing with cosign
Release images SHALL be signed using cosign keyless signing (Sigstore OIDC). The workflow SHALL request `id-token: write` permission.

#### Scenario: Signed release image
- **WHEN** the Docker image is pushed to GHCR
- **THEN** cosign signs the image digest with `cosign sign --yes`

### Requirement: Supply chain attestations
Release images SHALL include SLSA build provenance and SBOM attestations.

#### Scenario: Attestations present
- **WHEN** the Docker image is built
- **THEN** `provenance: true` and `sbom: true` are set on the build step

### Requirement: OCI annotations
Release images SHALL carry OCI annotations at the image-index level for description, source URL, and license.

#### Scenario: GHCR package description
- **WHEN** the multi-arch image index is pushed
- **THEN** `org.opencontainers.image.description`, `org.opencontainers.image.source`, and `org.opencontainers.image.licenses` annotations are present

### Requirement: Release concurrency
The release workflow SHALL never cancel an in-progress run (`cancel-in-progress: false`).

#### Scenario: Concurrent pushes to main
- **WHEN** two commits are pushed to main in quick succession
- **THEN** the second release workflow waits for the first to complete
