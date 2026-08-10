## ADDED Requirements

### Requirement: Trivy vulnerability scanning
The security workflow SHALL run Trivy against the built Docker image for CRITICAL and HIGH severity vulnerabilities.

#### Scenario: PR with dependency changes
- **WHEN** a PR modifies `Dockerfile`, `go.mod`, `go.sum`, or `.github/workflows/security.yml`
- **THEN** Trivy scans the image and uploads SARIF to the GitHub Security tab

#### Scenario: Weekly scan
- **WHEN** the weekly cron fires (Monday 06:00 UTC)
- **THEN** Trivy scans the latest image for new CVEs

#### Scenario: Manual scan
- **WHEN** the workflow is triggered via workflow_dispatch
- **THEN** Trivy scans the image

### Requirement: Report-only mode
Trivy SHALL use exit-code 0 — findings surface in the Security tab but never fail the pipeline.

#### Scenario: Vulnerability found
- **WHEN** Trivy finds a CRITICAL vulnerability
- **THEN** it appears in the GitHub Security tab but the workflow succeeds

### Requirement: SARIF upload
Trivy results SHALL be uploaded in SARIF format to the GitHub Security tab via `github/codeql-action/upload-sarif`.

#### Scenario: SARIF uploaded
- **WHEN** a Trivy scan completes (pass or fail)
- **THEN** the SARIF file is uploaded to the Security tab
