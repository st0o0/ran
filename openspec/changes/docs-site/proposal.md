## Why

The README is about 1000 lines and doubles as the reference documentation. A VitePress site gives a sidebar, search and one page per topic. The sibling projects FunkArr and njord already run VitePress with a shared deploy workflow, so the toolchain and the renovate preset are known.

## What Changes

- New `docs/` folder with a VitePress site, laid out like FunkArr and njord: `docs/package.json` (pinned `vitepress` and `vue`, `packageManager: pnpm@...`), `docs/pnpm-lock.yaml`, `docs/pnpm-workspace.yaml`, `docs/.vitepress/config.ts` (local search, sidebar, GitHub link), `docs/.vitepress/theme/` (own brand colors), `docs/public/` (logo). English only, no locale split.
- The `.gitignore` rule `docs/` ("design docs, local only") is replaced by ignores for `docs/node_modules/`, `docs/.vitepress/dist/` and `docs/.vitepress/cache/`. No local design docs exist today.
- Pages (stage 1): getting started, configuration, traps (generated table plus per-trap notes), classification and alerts, CrowdSec (profiles, escalation, behaviors to know), metrics, logging, hardening, upgrading, troubleshooting, comparison with alternatives.
- The README shrinks in stage 2 to pitch, comparison summary, quick start, trap list and links to the site. Until then the README stays complete.
- The trap table is generated from `config.DefaultPorts` and `config.AddresslessTraps` by a small Go tool (`go run ./internal/tools/docgen` or a `ran` subcommand) into `docs/traps.generated.md`; CI fails on `git diff --exit-code` after regeneration.
- Contract tests (`TestREADMEMatchesConfig`, `TestMaxTrackedDefaultIsConsistent`) read the README plus every `docs/**/*.md` page, so the guarantee does not lapse when content moves.
- Deploy: the release workflow gets a `docs` job that calls `st0o0/github-workflows/.github/workflows/docs.yml@main` (default `docs-path: docs`) after a release is created, like FunkArr. A PR build job runs `pnpm install --frozen-lockfile && pnpm run build` so broken links fail before merge. The owner enables GitHub Pages (source: GitHub Actions) in the repository settings.
- Renovate: `.github/renovate.json` additionally extends `local>st0o0/renovate-config:pnpm` (npm manager covers pnpm; groups VitePress, automerges minor and patch).

## Capabilities

### New Capabilities

- `docs-site`.

## Impact

- New `docs/` tree, `.gitignore`, `.github/workflows/release.yml` and a docs build check in CI, `.github/renovate.json`, `internal/config/contract_test.go`, a generator tool with a test, README (stage 2), `AGENTS.md` (how to build the site, generator rule).
- No change to the sensor binary or its behavior. The Docker image is unaffected (`docs/` must be excluded by `.dockerignore` if the build context copies the tree).

## Non-goals

- No locale split, no versioned docs, no custom Vue components in stage 1.
- No competitor numbers on the site until re-verified (Cowrie licence, OpenCanary protocol list, T-Pot container count); the comparison page keeps only facts checked against the projects' current repositories, with the check date.
- No custom domain (no `CNAME`) until the owner decides.
