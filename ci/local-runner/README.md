# Local CI runners

CI runs on ephemeral GitHub Actions runners on the maintainer's PC. Each
container registers with `--ephemeral`, runs exactly one job, and is restarted
fresh. Every container runs its own dockerd (DinD), so jobs that `docker compose
up` a cluster cannot collide with each other or with the host daemon.

Workflows target `runs-on: [self-hosted, kubernetes-rs]`.

## Start

```bash
# needs `gh auth login` on the host (repo admin); the token never enters a container
GITHUB_REPOSITORY=indyjonesnl/kubernetes-rs ci/local-runner/run-runners.sh 3
```

`run-runners.sh` builds the image, then per slot loops: mint a one-hour
registration token with `gh api`, `docker run --rm --privileged` a fresh runner
container, wait for its one job, repeat. Stop with Ctrl-C / `kill` (running
jobs are lost). Run it under `nohup`, tmux, or a systemd user unit to keep it
alive. Rebuild weekly (`docker build --pull ci/local-runner`) so the embedded
runner stays new enough to register.

## Notes

- `--privileged` is needed for the in-container dockerd. For stronger
  isolation install [sysbox](https://github.com/nestybox/sysbox) and swap it
  for `--runtime sysbox-runc` in `run-runners.sh`.
- Images pulled inside a runner persist across that container's restarts
  (per-slot `/var/lib/docker` volume); containers, networks and volumes a job
  leaves behind are removed at the next start. Remove the `kubernetes-rs-runner-*-docker` volumes to drop it all.
- `sccache` writes to the shared `sccache` volume, so ephemeral runners share
  compile results.
- Runners are x86_64 only. The arm64 image build in `publish-images.yml` still
  uses GitHub-hosted `ubuntu-24.04-arm`.
