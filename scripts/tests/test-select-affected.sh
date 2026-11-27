#!/usr/bin/env bash
# Unit test for scripts/ci/select-affected.sh against a synthetic workspace
# (core <- mid <- leaf <- devonly[dev-dep]; island; api-server <- core).
# No cargo, no network. Run: bash scripts/tests/test-select-affected.sh
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
S="$here/../ci/select-affected.sh"
M="$here/fixtures/select-affected-metadata.json"
fail=0
check() { # name expected-mode expected-packages [expected-sqlite] -- files...
  local name=$1 mode=$2 pk=$3 sq=$4; shift 5
  local out; out=$(printf '%s\n' "$@" | "$S" --metadata "$M")
  local gm gp gs
  gm=$(sed -n 's/^mode=//p' <<<"$out"); gp=$(sed -n 's/^packages=//p' <<<"$out"); gs=$(sed -n 's/^sqlite=//p' <<<"$out")
  if [ "$gm" = "$mode" ] && [ "$gp" = "$pk" ] && { [ -z "$sq" ] || [ "$gs" = "$sq" ]; }; then echo "ok   $name"
  else echo "FAIL $name: got mode=$gm packages='$gp' sqlite=$gs"; fail=1; fi
}
check leaf-only          scoped "-p devonly -p leaf" ""    -- crates/leaf/src/lib.rs
check mid-closure        scoped "-p devonly -p leaf -p mid" "" -- crates/mid/Cargo.toml
check island-no-prefix   scoped "-p island"  false -- crates/island/src/a.rs
check prefix-sibling     scoped "-p prefix"  false -- crates/island-ext/src/a.rs
check core-closure-sqlite scoped "-p core -p devonly -p kubernetes-rs-api-server -p leaf -p mid" true -- crates/core/src/x.rs
check dedupe-sorted      scoped "-p devonly -p leaf -p mid" "" -- crates/mid/a.rs crates/leaf/b.rs crates/mid/a.rs
check docs-only          none   "" "" -- README.md docs/CI.md
check inert-workflow     none   "" "" -- .github/workflows/conformance-sig-node.yml scripts/foo.sh
check md-plus-crate      scoped "-p island" "" -- docs/x.md crates/island/src/a.rs
check cargo-lock         full   "" "" -- Cargo.lock crates/leaf/src/a.rs
check root-cargo-toml    full   "" "" -- Cargo.toml
check toolchain          full   "" "" -- rust-toolchain.toml
check cargo-config       full   "" "" -- .cargo/config.toml
check ci-dir             full   "" "" -- ci/local-runner/Dockerfile
check own-workflow       full   "" "" -- .github/workflows/test.yml
check ci-scripts         full   "" "" -- scripts/ci/select-affected.sh
check common             full   "" "" -- crates/common/src/lib.rs
check upstream-fixtures  full   "" "" -- tests/upstream/k8s-1.35/x.json
check unknown-top-level  full   "" "" -- weird/file
check unowned-crate-dir  full   "" "" -- crates/brand-new/src/lib.rs
out=$(printf 'README.md\n' | "$S" --force-full --metadata "$M"); grep -q '^mode=full' <<<"$out" && echo "ok   force-full" || { echo "FAIL force-full"; fail=1; }
exit $fail
