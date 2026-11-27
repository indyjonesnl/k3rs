#!/usr/bin/env bash
# Decide how much of the workspace a pull request must compile and test.
#
# Usage:
#   select-affected.sh [--files FILE|-] [--metadata FILE] [--force-full]
#
#   --files FILE     newline-separated changed paths (repo-relative); `-` or
#                    omitted reads stdin.
#   --metadata FILE  `cargo metadata --no-deps --format-version 1` output;
#                    omitted runs cargo metadata itself (offline, no build).
#   --force-full     skip analysis, mode=full (label `ci:full`, push, cron...).
#
# Output on stdout (KEY=VALUE, also safe to append to $GITHUB_OUTPUT):
#   mode=full|scoped|none
#       full   -> run the whole workspace (`--workspace`)
#       scoped -> run only `packages`
#       none   -> no Rust affected (docs / inert files only); fmt still runs
#   packages=-p a -p b      (scoped only; empty otherwise)
#   sqlite=true|false       whether `kubernetes-rs-api-server/sqlite` may be
#                           passed: cargo rejects `--features pkg/feat` when pkg
#                           is not among the selected `-p` packages.
#   reason=...              (human readable, first rule that decided it)
#
# Deterministic: same inputs -> same output, packages sorted. Pure bash+jq,
# no network, no build. Tested by scripts/tests/test-select-affected.sh.
# Rules are documented in docs/CI.md.
set -euo pipefail

files_arg=-
metadata_file=
force_full=0
while [ $# -gt 0 ]; do
  case "$1" in
    --files) files_arg=$2; shift 2 ;;
    --metadata) metadata_file=$2; shift 2 ;;
    --force-full) force_full=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

emit() { # mode packages reason [sqlite]
  printf 'mode=%s\npackages=%s\nreason=%s\nsqlite=%s\n' "$1" "$2" "$3" "${4:-true}"
}

if [ "$force_full" = 1 ]; then emit full "" "forced full run"; exit 0; fi

if [ "$files_arg" = - ]; then files=$(cat); else files=$(cat "$files_arg"); fi
files=$(printf '%s\n' "$files" | sed '/^$/d' | LC_ALL=C sort -u)
if [ -z "$files" ]; then emit none "" "no changed files"; exit 0; fi

if [ -n "$metadata_file" ]; then meta=$(cat "$metadata_file")
else meta=$(cargo metadata --no-deps --format-version 1 --offline); fi

root=$(printf '%s' "$meta" | jq -r '.workspace_root')

# Workspace members as "name<TAB>repo-relative dir".
members=$(printf '%s' "$meta" | jq -r --arg root "$root/" '
  .packages[] | [.name, (.manifest_path | sub("/Cargo.toml$"; "") | sub("^" + $root; ""))] | @tsv')

full_reason=
seeds=
while IFS= read -r f; do
  case "$f" in
    # Workspace-global inputs: anything here can change every crate.
    Cargo.toml|Cargo.lock|rust-toolchain|rust-toolchain.toml|.cargo/*|ci/*|scripts/ci/*|\
    .github/workflows/test.yml|.github/workflows/fmt.yml|rhino|rhino/*)
      full_reason="workspace-global file changed: $f"; break ;;
    # Files that crates read at build/test time from outside their own dir
    # (include_str!, CARGO_MANIFEST_DIR/../.. fixtures, script invocations).
    tests/*|bootstrap-cluster.yaml|manifests/*|deploy/*|scripts/wire-format-coverage.sh|scripts/gen-protobuf*)
      full_reason="cross-crate input changed: $f"; break ;;
    # crates/common: every crate depends on it (directly or transitively) and
    # its test fixtures are read by api-server; the reverse-dep set is
    # ~the whole workspace, so skip the expansion and run everything.
    crates/common/*)
      full_reason="crates/common changed (everything depends on it): $f"; break ;;
    # Inert for Rust: docs, markdown, container/compose files, scripts that
    # are not read by tests, other workflows (own linters), local tooling.
    *.md|docs/*|LICENSE|NOTICE|Makefile|Dockerfile|*.Dockerfile|compose*.yml|docker-compose*.yml|\
    haproxy.cfg|kubeconfig.example.yaml|cni-config/*|examples/*|console/*|tools/*|\
    .github/*|scripts/*|indy/*|.gitignore|.dockerignore)
      continue ;;
    crates/*)
      # Longest member dir that prefixes the path.
      hit=$(printf '%s\n' "$members" | awk -F'\t' -v f="$f" \
        'index(f, $2 "/") == 1 && length($2) > best { best = length($2); name = $1 } END { print name }')
      if [ -z "$hit" ]; then
        full_reason="path under crates/ not owned by a workspace member: $f"; break
      fi
      seeds="$seeds$hit"$'\n' ;;
    *)
      # Unknown top-level path: fail safe.
      full_reason="unclassified path (fail-safe full run): $f"; break ;;
  esac
done <<< "$files"

if [ -n "$full_reason" ]; then emit full "" "$full_reason"; exit 0; fi
seeds=$(printf '%s' "$seeds" | sed '/^$/d' | LC_ALL=C sort -u)
if [ -z "$seeds" ]; then emit none "" "only non-Rust files changed"; exit 0; fi

# Reverse-dependency closure over workspace members. `dependencies` in
# `cargo metadata` includes normal, dev and build deps, which is what we want:
# a dev-dependency edge means the dependent's tests exercise the changed crate.
affected=$(printf '%s' "$meta" | jq -r --argjson seeds \
  "$(printf '%s' "$seeds" | jq -R . | jq -s .)" '
  [.packages[] | {name, deps: [.dependencies[].name]}] as $pk
  | def grow($set): ($set + [$pk[] | select(any(.deps[]; . as $d | $set | index($d))) | .name] | unique);
    def fix($set): grow($set) as $n | if $n == $set then $set else fix($n) end;
  fix($seeds | unique) | .[]' | LC_ALL=C sort -u)

pkgs=
while IFS= read -r p; do pkgs="$pkgs${pkgs:+ }-p $p"; done <<< "$affected"
sqlite=false
if printf '%s\n' "$affected" | grep -qx 'kubernetes-rs-api-server'; then sqlite=true; fi
emit scoped "$pkgs" "scoped to $(printf '%s\n' "$seeds" | paste -sd, -) plus reverse dependencies" "$sqlite"
