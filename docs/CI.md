# CI: scoped pull requests

Workflow: `.github/workflows/test.yml` (jobs `cargo clippy`, `cargo nextest`,
aggregate `cargo clippy + nextest`) and `.github/workflows/fmt.yml`
(`Verify formatting with cargo fmt`). Runners: `ci/local-runner/`.

The merge ruleset requires the checks `Verify formatting with cargo fmt`,
`cargo clippy` and `cargo nextest`. Job names and ids must not change.

## When the whole workspace runs

| Trigger | Scope |
|---|---|
| push to `main` | full workspace |
| nightly cron (03:17 UTC) | full workspace |
| `workflow_dispatch` | full workspace |
| pull request with the `ci:full` label | full workspace |
| pull request | scoped (below) |

A scoped miss is therefore caught on `main` or by the nightly run.

## How a pull request is scoped

`scripts/ci/select-affected.sh` maps `git diff --name-only <base>...HEAD` to
workspace crates, expands to reverse dependencies (normal, dev and build edges
from `cargo metadata --no-deps`), and runs
`cargo clippy -p a -p b ...` and `cargo nextest run -p a -p b ...`.
`scripts/ci/detect-scope.sh` is the workflow wrapper. Unit test:
`bash scripts/tests/test-select-affected.sh` (no build needed).

First matching rule per file; any file that selects "full" wins over scoping:

| Changed path | Result |
|---|---|
| `Cargo.toml`, `Cargo.lock`, `rust-toolchain*`, `.cargo/**`, `ci/**`, `scripts/ci/**`, `.github/workflows/test.yml`, `.github/workflows/fmt.yml`, `rhino*` | full |
| `crates/common/**` | full (every crate depends on it; its fixtures are read by api-server) |
| `tests/**`, `manifests/**`, `deploy/**`, `bootstrap-cluster.yaml`, `scripts/wire-format-coverage.sh`, `scripts/gen-protobuf*` | full (read by crate tests from outside their own directory) |
| `crates/<member>/**` | that crate plus all workspace crates that depend on it |
| a path under `crates/` that is not a workspace member | full |
| `*.md`, `docs/**`, Dockerfiles, compose files, `.github/**` (other workflows), other `scripts/**`, `examples/**`, `console/**`, `tools/**`, `indy/**` | no Rust (fmt only) |
| anything else | full (fail safe) |

`kubernetes-rs-api-server/sqlite` is only passed to nextest when the api-server
is in the selected set (cargo rejects `--features pkg/feat` for a package
outside `-p`). The wire-format coverage report only runs in full mode.

When no Rust is affected the `clippy` and `nextest` jobs still run and report
success in seconds, so the required checks always report.
The aggregate job requires both to be `success`: a failed, cancelled or
skipped job turns it red.

## Known gaps of scoping

- A test that scans other crates' sources (for example
  `crates/controller-manager/tests/it/update_carries_stored_identity_guard_test.rs`)
  only runs when its own crate is affected.
- `cargo check --workspace` is deliberately not run on PRs: every dependent of
  a changed crate is already compiled and linted, so it adds no compile safety
  for a scoped PR, and a full workspace check costs about as much as the full
  clippy job (about 2.6 min plus a 2-3 min cache restore on an idle runner).

## Forcing a full run

Add the `ci:full` label to the PR and re-run the `Rust tests` workflow (the
label is read live from the API when the job starts, so it also works for a
re-run). Pushing a new commit works too.

## Rollback

Revert the PR that introduced this section: `test.yml` returns to
`cargo clippy --workspace` / `cargo nextest run --workspace` on every Rust PR.
