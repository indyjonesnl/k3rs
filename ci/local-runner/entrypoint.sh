#!/usr/bin/env bash
# One-shot ephemeral runner: start a private dockerd, register with GitHub,
# run ONE job, deregister (automatic with --ephemeral), exit.
set -euo pipefail

: "${GITHUB_REPOSITORY:?e.g. indyjonesnl/kubernetes-rs}"
: "${GITHUB_PAT:?PAT with repo (or Administration:write on the repo) scope}"
RUNNER_LABELS="${RUNNER_LABELS:-kubernetes-rs}"
RUNNER_NAME="${RUNNER_NAME_PREFIX:-kubernetes-rs}-$(hostname)"

# --- private dockerd (needs --privileged or a sysbox runtime) ----------------
rm -f /var/run/docker.pid
sudo env PATH="$PATH" /usr/bin/dockerd --host=unix:///var/run/docker.sock >/tmp/dockerd.log 2>&1 &
for _ in $(seq 1 60); do docker info >/dev/null 2>&1 && break; sleep 1; done
docker info >/dev/null 2>&1 || { echo "dockerd failed:"; cat /tmp/dockerd.log; exit 1; }

# --- registration token ------------------------------------------------------
TOKEN="$(curl -fsSL -X POST \
  -H "Authorization: Bearer ${GITHUB_PAT}" \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/${GITHUB_REPOSITORY}/actions/runners/registration-token" \
  | jq -r .token)"

cd /home/runner
# Container is restarted (not recreated) between jobs: drop the previous
# registration + job workspace, and any containers/networks/volumes a job left
# in the private dockerd (images stay cached).
rm -rf .runner .credentials .credentials_rsaparams _work
docker ps -aq | xargs -r docker rm -f >/dev/null 2>&1 || true
docker network prune -f >/dev/null 2>&1 || true
docker volume prune -af >/dev/null 2>&1 || true
./config.sh --unattended --ephemeral --replace \
  --url "https://github.com/${GITHUB_REPOSITORY}" \
  --token "${TOKEN}" \
  --name "${RUNNER_NAME}" \
  --labels "${RUNNER_LABELS}" \
  --work _work

cleanup() { ./config.sh remove --token "${TOKEN}" >/dev/null 2>&1 || true; sudo pkill dockerd || true; }
trap cleanup EXIT
./run.sh
