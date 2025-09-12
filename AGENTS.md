# Repository Guidelines

## Project Structure & Module Organization
- Go module: `k8sgateway`. Runtime code in `cmd/` (CLI entry) and `internal/` (packages: `connect`, `httpproxy`, `metrics`, `token`, `wsproxy`, `log`, `version`).
- Helm chart: `deploy/gateway/` (templates, values, and `tests/` for `helm-unittest`).
- Tests: unit alongside code in `cmd/` and `internal/`; integration in `test/integration/`; e2e in `test/e2e/`; test data in `test/data/`.
- Release artifacts and local builds land in `dist/` (via GoReleaser).

## Build, Test, and Development Commands
- `make help` — show available targets and variables.
- `make lint` — run `golangci-lint` with autofix.
- `make test` / `make test-with-coverage` — unit tests (coverage profile written).
- `make test-integration` — integration tests (requires Docker and Caddy running on localhost).
- `make test-e2e` — end-to-end tests.
- `make test-helm` — run Helm chart tests; `make test-helm-and-update-snapshots` updates snapshots.
- `make build` — snapshot build via GoReleaser (binaries + multi-arch Docker images).
- `make cut-release` / `make cut-release-prod` — tag dev/prod releases on `master` using `svu`.

## Coding Style & Naming Conventions
- Go 1.25.0 (see `.tool-versions`). `.editorconfig` enforces tabs for `*.go`, spaces for Markdown.
- Format/lint: `golangci-lint run --fix ./...` (imports ordered by `gci`). CI checks `gofmt -s` and `go vet`.
- Packages use short, lower-case names. Keep commands in `cmd/<name>` and domain code in `internal/<domain>`.

## Testing Guidelines
- Frameworks: standard `testing` with `testify`. Name files `*_test.go` and tests `TestXxx`.
- Coverage: prefer meaningful assertions; CI publishes combined coverage to Coveralls.
- Helm: keep chart tests green; update snapshots only when templates intentionally change.

## Commit & Pull Request Guidelines
- PR titles must follow Conventional Commits (CI-enforced). Example: `feat(proxy): add JWT audience check`.
- Use the PR template; provide a clear summary, linked issues, and repro steps or screenshots for fixes. Danger will fail placeholder text.
- Keep changes focused; ensure lint, unit/integration/e2e, and Helm tests pass.

## Security & Configuration Tips
- Never commit secrets. Use environment variables; `.envrc` (direnv) is supported for local dev.
- Published images follow `twingate/kubernetes-access-gateway:<tag>`; keep `deploy/gateway/values.schema.json` in sync with image/tag and config changes.

