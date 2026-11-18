#!/usr/bin/env bash
# One-shot: certs → build → stage → boot → sync → bootstrap.
# Local-first (see CLAUDE.local.md): `make build-fast`, incremental, no sccache.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
export CARGO_INCREMENTAL=1; unset RUSTC_WRAPPER

[ -f "$ROOT/.k3rs/certs/ca.crt" ] || bash "$ROOT/scripts/generate-certs.sh"
# front-proxy PKI is part of the api-server flag set
[ -f "$ROOT/.k3rs/certs/front-proxy-ca.crt" ] || bash "$ROOT/scripts/generate-certs.sh"

if [ -z "${SKIP_BUILD:-}" ]; then
  for spec in "k3rs-api-server api-server" "k3rs-scheduler scheduler" \
              "k3rs-controller-manager controller-manager" "k3rs-kubelet kubelet" "k3rs-kube-proxy kube-proxy"; do
    set -- $spec
    make -C "$ROOT" build-fast ARGS="-p $1 --bin $2"
  done
  if [ ! -x "$HERE/dist/bin/rhino-server" ]; then
    rev="$(sed -n 's/^ARG RHINO_REV=//p' "$ROOT/rhino.Dockerfile")"
    cargo install --git https://github.com/indyjonesnl/rhino.git --rev "$rev" rhino --bin rhino-server --locked --root "$HERE/dist"
  fi
fi

cp "$ROOT/deploy/containerd/config.toml" "$HERE/build/payload/containerd-config.toml"
"$MC" -f "$HERE/compose.yaml" up
"$HERE/sync.sh"

export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/k3rs-config}"
echo "api-server on https://127.0.0.1:6443 ; KUBECONFIG=$KUBECONFIG"
echo "next: bash scripts/bootstrap-cluster.sh   (CoreDNS/kube-dns, SA tokens)"
