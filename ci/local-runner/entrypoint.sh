#!/usr/bin/env bash
# One-shot ephemeral runner: start a private dockerd, register with GitHub,
# run ONE job, deregister (automatic with --ephemeral), exit.
set -euo pipefail

: "${GITHUB_REPOSITORY:?e.g. indyjonesnl/kubernetes-rs}"
: "${RUNNER_TOKEN:?short-lived registration token, minted by run-runners.sh}"
RUNNER_LABELS="${RUNNER_LABELS:-kubernetes-rs}"
RUNNER_NAME="${RUNNER_NAME_PREFIX:-kubernetes-rs}-$(hostname)"

# One container per job (docker run --rm): nothing survives. The only secret
# present is a one-time registration token, already spent by config.sh.
# --- private dockerd (needs --privileged or a sysbox runtime) ----------------
# The compose stacks bind-mount the kubelet volumes path with `rshared`
# (compose.sqlite.yml, emptyDir tmpfs propagation, #445); dockerd refuses that
# unless the container's `/` is a shared mount. Docker hosts default to private.
sudo mount --make-rshared /
# cgroup v2 nesting for the private dockerd (as docker:dind's entrypoint does):
# on a cgroup v2 host the container's root cgroup holds this process, and the
# "no internal processes" rule then stops dockerd from delegating controllers to
# the containers it runs. Without this, systemd in a `kind` node container never
# boots ("could not find a log line that matches \"Reached target .*Multi-User
# System.*\""). Move everything into an `init` leaf and enable the controllers.
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
  sudo bash -c 'mkdir -p /sys/fs/cgroup/init
    xargs -rn1 < /sys/fs/cgroup/cgroup.procs > /sys/fs/cgroup/init/cgroup.procs || :
    sed -e "s/ / +/g" -e "s/^/+/" < /sys/fs/cgroup/cgroup.controllers > /sys/fs/cgroup/cgroup.subtree_control'
fi
rm -f /var/run/docker.pid
sudo env PATH="$PATH" /usr/bin/dockerd --host=unix:///var/run/docker.sock >/tmp/dockerd.log 2>&1 &
for _ in $(seq 1 60); do docker info >/dev/null 2>&1 && break; sleep 1; done
docker info >/dev/null 2>&1 || { echo "dockerd failed:"; cat /tmp/dockerd.log; exit 1; }

# Named volumes are created root-owned; sccache runs as `runner`.
sudo chown runner:runner /cache/sccache 2>/dev/null || true

cd /home/runner
# /var/lib/docker is a per-slot volume reused across containers: drop any
# containers/networks/volumes an earlier job left in it (images stay cached).
rm -rf .runner .credentials .credentials_rsaparams _work
docker ps -aq | xargs -r docker rm -f >/dev/null 2>&1 || true
docker network prune -f >/dev/null 2>&1 || true
docker volume prune -af >/dev/null 2>&1 || true
./config.sh --unattended --ephemeral --replace \
  --url "https://github.com/${GITHUB_REPOSITORY}" \
  --token "${RUNNER_TOKEN}" \
  --name "${RUNNER_NAME}" \
  --labels "${RUNNER_LABELS}" \
  --work _work

# --ephemeral runners deregister themselves after their job.
cleanup() { sudo pkill dockerd || true; }
trap cleanup EXIT
unset RUNNER_TOKEN
./run.sh
