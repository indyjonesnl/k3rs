#!/bin/bash
# Ported from k3s scripts/airgap/generate-list.sh: regenerate image-list.txt from
# the images present on the running kubernetes-rs nodes (union of `crictl images` repoTags[0]
# across node-1 and node-2, the same query tests basics_test.go VerifyAirgapImages makes).
# k3s runs `k3s crictl images` in its single server container; a kubernetes-rs node is several
# containers, so crictl is run in the first container of each node that has it.
set -e -x

cd "$(dirname "$0")"

DOCKER="${DOCKER:-docker}"
for node_containers in "kubernetes-rs-kubelet kubernetes-rs-containerd kubernetes-rs-kube-proxy" "kubernetes-rs-kubelet2 kubernetes-rs-containerd2 kubernetes-rs-kube-proxy2"; do
  for c in $node_containers; do
    if "$DOCKER" exec "$c" crictl --version >/dev/null 2>&1; then
      "$DOCKER" exec "$c" crictl images -o json
      break
    fi
  done
done | jq -r '.images[].repoTags[0] | select(. != null)' | sort -u | tee image-list.txt
