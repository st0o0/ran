## 1. Scaffold

- [x] 1.1 `docs/package.json` (pinned `vitepress`, `vue`, `packageManager`), `pnpm-workspace.yaml`, lockfile, `.vitepress/config.ts`, theme colors, logo
- [x] 1.2 `.gitignore`: replace `docs/` with `docs/node_modules/`, `docs/.vitepress/dist/`, `docs/.vitepress/cache/`; check `.dockerignore`
- [x] 1.3 Verify the local build (`pnpm install --frozen-lockfile && pnpm run build`), no dead links

## 2. Content (stage 1)

- [x] 2.1 Pages: getting started, configuration, traps, classification and alerts, CrowdSec, metrics, logging, hardening, upgrading, troubleshooting, comparison (checked facts only, with date)
- [x] 2.2 Generator for the trap table and drift test
- [x] 2.3 Contract tests read README plus `docs/**/*.md`

## 3. CI and deploy

- [x] 3.1 Docs build job on pull requests
- [x] 3.2 `docs` job in `release.yml` calling the shared `docs.yml`
- [x] 3.3 `.github/renovate.json` extends the pnpm preset
- [x] 3.4 `AGENTS.md`: build command, generator rule, contract scope

## 4. Verification and stage 2

- [ ] 4.1 `go test ./...`, 386 build, lint, `openspec validate --all`
- [ ] 4.2 Owner enables GitHub Pages (Actions source); check the live site
- [ ] 4.3 Shrink the README to pitch, quick start, trap list and links
