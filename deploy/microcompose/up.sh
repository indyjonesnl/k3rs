#!/usr/bin/env bash
# One-shot: build k3rs → bake/boot → sync (server, token, agents).
# Local-first (see CLAUDE.local.md): `make build-fast`, incremental, no sccache.
# No certs, no rhino, no bootstrap script: `k3rs server` mints its PKI, join
# token and bootstrap objects (kube-dns Service etc.) itself.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
export CARGO_INCREMENTAL=1; unset RUSTC_WRAPPER

[ -n "${SKIP_BUILD:-}" ] || make -C "$ROOT" build-fast ARGS="-p k3rs --bin k3rs"

cp "$ROOT/deploy/containerd/config.toml" "$HERE/build/payload/containerd-config.toml"
"$MC" -f "$HERE/compose.yaml" up
"$HERE/sync.sh"

echo "k3rs server on https://127.0.0.1:6443 (forwarded from node1)"
echo "next: ./acceptance.sh   (writes ./.kubeconfig from node1:/var/lib/k3rs/tls/admin.kubeconfig)"
