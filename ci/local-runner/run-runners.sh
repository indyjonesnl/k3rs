#!/usr/bin/env bash
# Keep N ephemeral runner containers alive on this host.
#   ci/local-runner/run-runners.sh [N=3]
# Per job: mint a one-hour registration token with the host's `gh` login,
# `docker run --rm --privileged` a fresh runner container (own dockerd), wait
# for it to finish its single job, repeat. The PAT/gh token never enters a
# container, so job code cannot read it.
set -uo pipefail
N="${1:-3}"
REPO="${GITHUB_REPOSITORY:-indyjonesnl/kubernetes-rs}"
IMAGE=kubernetes-rs-local-runner:latest
DIR="$(cd "$(dirname "$0")" && pwd)"

docker build -q -t "$IMAGE" "$DIR" >/dev/null || exit 1
docker volume create kubernetes-rs-sccache >/dev/null

slot() {
  local i="$1"
  docker volume create "kubernetes-rs-runner-$i-docker" >/dev/null
  while true; do
    tok="$(gh api -X POST "repos/${REPO}/actions/runners/registration-token" --jq .token)" \
      || { echo "[slot $i] token mint failed; retry in 30s" >&2; sleep 30; continue; }
    docker run --rm --privileged --name "kubernetes-rs-runner-$i" \
      -e GITHUB_REPOSITORY="$REPO" -e RUNNER_TOKEN="$tok" \
      -e RUSTC_WRAPPER=sccache -e SCCACHE_DIR=/cache/sccache -e SCCACHE_CACHE_SIZE=20G \
      -v kubernetes-rs-sccache:/cache/sccache \
      -v "kubernetes-rs-runner-$i-docker:/var/lib/docker" \
      --cpus 8 --memory 16g \
      "$IMAGE" || sleep 10
  done
}

trap 'kill 0' EXIT INT TERM
for i in $(seq 1 "$N"); do slot "$i" & done
wait
