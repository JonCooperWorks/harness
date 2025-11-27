# Repository Guidelines

## Project Structure & Module Organization
Source lives under `cmd/`, with dedicated entry points such as `cmd/harness` (runtime), `cmd/sign` and `cmd/verify` (artifact tooling), and `cmd/genkeys` (keypair generation). Shared crypto helpers and keystore adapters are in `crypto/` with platform-specific code under `crypto/keystore/`. Sample plugins and fixtures live in `plugin/` (`plugin/test` for host-side mocks, `plugin/wasm` for compiled modules). Generated binaries drop into `bin/` when you run `go build`, while signing materials (`*_private.pem`, `*_public.pem`) sit at the repo root.

## Build, Test, and Development Commands
- `go build ./cmd/...` – compile every CLI into `bin/` for local use.
- `go test ./...` – run unit tests across `crypto`, plugin loaders, and supporting packages.
- `go run ./cmd/harness -file test-plugin.encrypted -key harness_private.pem -president-key president_public.pem -args '{"message":"hi"}'` – quick manual smoke test that exercises the decrypt/execute flow.
- `go run ./cmd/sign -plugin plugin/wasm/test-plugin.wasm -type wasm ...` – re-sign fixtures when plugin code changes.

## Coding Style & Naming Conventions
Write Go 1.21-compatible code formatted with `gofmt`; favor gofumpt-tight imports for consistent spacing. Use PascalCase for exported types/functions, camelCase for locals, and kebab-case for CLI flags. Directory names mirror component intent (`harness`, `verify`, `keystore`); follow that pattern for new modules. Keep error messages lowercase and actionable, and prefer wrapping (`fmt.Errorf("...: %w", err)`) when propagating failures.

## Testing Guidelines
Unit tests should live next to the code they cover (`foo_test.go`) and follow the `TestXxx` naming convention. Include table-driven tests for crypto edge cases and keystore adapters. For integration coverage, extend `cmd/test-roundtrip` or add new scenarios that sign, verify, and execute a WASM. Ensure `go test ./...` passes before opening a PR and include encrypted companions for any new `.wasm` fixtures under `plugin/wasm/`.

## Commit & Pull Request Guidelines
Commits in this repo use short, imperative subjects (`fix keystore unlock`). Group related changes together and include rationale in the body when touching security-sensitive code. PRs must describe the threat model impact, list key commands executed (build/test), and note any new assets or keys added. Link tracking issues when available and provide CLI transcripts for harness behavior changes. Await one approving review before merging.

## Security & Configuration Tips
Treat the PEM files as development-only. Prefer OS keystore integration (see `crypto/keystore/`) for anything beyond local testing, and never check real production keys into the repo. When sharing encrypted plugins, always include the corresponding signature metadata so `cmd/verify` can run offline.
