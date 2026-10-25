## 1. Register

- [x] 1.1 `config.Settings` with all variables and per-trap families; drift tests (names, defaults, generated file)
- [x] 1.2 `docgen` writes `docs/data/settings.generated.json` (stable order) and `docs/data/builder-cases.json`
- [x] 1.3 Go test replays `builder-cases.json` through `config.Load`

## 2. Builder logic (TypeScript, vitest)

- [ ] 2.1 `docs/.vitepress/theme/builder/{types,state,rules,serializer,hash}.ts` with unit tests: delta export, env/Compose/`docker run`, import of env files, hash round trip, broken hash, non-Latin-1 input
- [ ] 2.2 Rules replay `builder-cases.json`
- [ ] 2.3 Scenarios (`direct`, `reverse-proxy`, `shared-namespace`, `crowdsec`)

## 3. Page

- [ ] 3.1 `ConfigBuilder.vue` and `docs/builder.md`, registered in the theme; nav and sidebar entries; mobile layout
- [ ] 3.2 Reverse proxy hints (Caddy), CrowdSec placeholder note, log volume hint for UDP and wide port sets
- [ ] 3.3 Getting started links to the builder

## 4. Verification

- [ ] 4.1 CI docs job runs the vitest suite; `AGENTS.md` note (new variable needs a register entry)
- [ ] 4.2 `go test ./...`, `GOARCH=386` vet, lint, `openspec validate --all`, docs build
