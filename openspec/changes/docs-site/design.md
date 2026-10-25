## Layout

`docs/` mirrors FunkArr and njord so one mental model and the shared `docs.yml` workflow apply. The folder name matters: the shared workflow defaults to `docs-path: docs`, and both reference projects use it.

## Generated content

Only what can drift is generated: the trap table (name, default port, transport, address variable for addressless traps). Everything else is prose. The generator reads `config.DefaultPorts` and `config.AddresslessTraps` (the same sources as `registry_test.go`), writes deterministic Markdown (sorted, LF line endings) and a test runs it against the committed file, so `go test` already catches drift and CI needs no extra step beyond the test.

## Contract tests

`TestREADMEMatchesConfig` collects `RAN_*` references from the README and requires every config variable to be documented. It will read README plus all `docs/**/*.md` (excluding `node_modules`) and concatenate them. Removing a variable from the docs while it stays in config still fails.

## Migration

1. Stage 1: add the site with full content, keep the README as is. Both are complete, so no information is lost if the site is late.
2. Stage 2: shrink the README to pitch, quick start, trap list and links, once the site is live and the links are verified.

## Risks

- Duplicated content between README and site during stage 1 can diverge; the contract test covers variables only. Stage 2 should follow soon.
- Pages needs a repository setting that only the owner can change.
- Node toolchain only in CI for docs; the Go build and the image are untouched.
