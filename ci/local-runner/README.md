# Local CI runners

CI runs on ephemeral GitHub Actions runners on the maintainer's PC. Each
container registers with `--ephemeral`, runs exactly one job, and is restarted
fresh. Every container runs its own dockerd (DinD), so jobs that `docker compose
up` a cluster cannot collide with each other or with the host daemon.

Workflows target `runs-on: [self-hosted, kubernetes-rs]`.

## Start

```bash
cd ci/local-runner
cp .env.example .env        # set GITHUB_PAT (repo admin: Administration read/write)
docker compose up -d --build --scale runner=3
docker compose logs -f
```

Stop: `docker compose down`. Rebuild weekly (`docker compose build --pull`) so
the embedded runner stays new enough to register.

## Notes

- `privileged: true` is needed for the in-container dockerd. For stronger
  isolation install [sysbox](https://github.com/nestybox/sysbox) and swap it
  for `runtime: sysbox-runc`.
- Images pulled inside a runner persist across that container's restarts
  (anonymous `/var/lib/docker` volume); containers, networks and volumes a job
  leaves behind are removed at the next start. `docker compose down` drops it all.
- `sccache` writes to the shared `sccache` volume, so ephemeral runners share
  compile results.
- Runners are x86_64 only. The arm64 image build in `publish-images.yml` still
  uses GitHub-hosted `ubuntu-24.04-arm`.
