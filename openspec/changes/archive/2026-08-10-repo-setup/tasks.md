## 1. Release-please Configuration

- [x] 1.1 Create `release-please-config.json` with `release-type: simple` and single root package
- [x] 1.2 Create `.release-please-manifest.json` with initial version `0.0.0`

## 2. Commit Convention Configuration

- [x] 2.1 Create `commitlint.config.mjs` with allowed types (feat, fix, perf, docs, chore, refactor, style, test, ci, build, deps), relaxed style rules, and dependabot ignore
- [x] 2.2 Create `package.json` with `@commitlint/config-conventional` devDependency (needed by commitlint action)

## 3. Linter Configuration

- [x] 3.1 Create `.golangci.yml` with v2 config and base exclusion presets (no project-specific suppressions)
- [x] 3.2 Create `.hadolint.yaml` with warning threshold and DL3018 ignored

## 4. CI/CD Workflows

- [x] 4.1 Create `.github/workflows/ci.yml` — PR-only pipeline with unit, lint, build (smoke test: `ran` without args → exit 1), and e2e jobs
- [x] 4.2 Create `.github/workflows/release.yml` — push-to-main pipeline with release-please + multi-arch Docker build (amd64, arm64) to `ghcr.io/st0o0/ran` with cosign signing, SLSA provenance, and SBOM
- [x] 4.3 Create `.github/workflows/dev-build.yml` — label-gated (`dev-build`) PR dev image publishing to GHCR with environment approval and PR comment
- [x] 4.4 Create `.github/workflows/security.yml` — Trivy scan on dependency changes + weekly cron + manual, SARIF upload, report-only mode
- [x] 4.5 Create `.github/workflows/commitlint.yml` — PR commit message validation

## 5. Dependabot

- [x] 5.1 Create `.github/dependabot.yml` with gomod, github-actions, and docker ecosystems (weekly, `deps` prefix, grouped)

## 6. Community & Templates

- [x] 6.1 Create `.github/PULL_REQUEST_TEMPLATE.md` with conventional commit checklist
- [x] 6.2 Create `.github/ISSUE_TEMPLATE/bug_report.yml` adapted for ran (honeypot-specific fields)
- [x] 6.3 Create `.github/ISSUE_TEMPLATE/feature_request.yml`
- [x] 6.4 Create `.github/ISSUE_TEMPLATE/config.yml` with security advisory and discussions links
- [x] 6.5 Create `CONTRIBUTING.md` with dev setup, PR workflow, and conventions
- [x] 6.6 Create `SECURITY.md` with supported versions and private reporting instructions
- [x] 6.7 Create `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1)
