# Self-hosted GitHub Actions runner image for kubernetes-rs CI.
#
# One container == one job: the entrypoint registers an --ephemeral runner,
# runs exactly one job, and exits; compose restarts it as a fresh container.
# Each container runs its OWN dockerd (Docker-in-Docker, started by
# entrypoint.sh), so a job's `docker compose up` stacks, networks and images
# die with the container and concurrent jobs cannot collide on the host daemon.
#
# Pre-bakes: Rust stable (+clippy, rustfmt), cargo-nextest, sccache, protoc,
# mold + clang, docker engine + compose plugin, jq, kubectl-free (workflows
# fetch what else they need).
#
# Build/run: see ci/local-runner/README.md.
FROM ghcr.io/actions/actions-runner:latest

USER root

ARG TARGETARCH
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends \
      protobuf-compiler libprotobuf-dev \
      mold clang \
      pkg-config libssl-dev \
      build-essential \
      jq curl ca-certificates git gnupg iptables uidmap \
 && install -m 0755 -d /etc/apt/keyrings \
 && curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc \
 && echo "deb [signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
      > /etc/apt/sources.list.d/docker.list \
 && apt-get update -qq \
 && apt-get install -y --no-install-recommends \
      docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin \
 && rm -rf /var/lib/apt/lists/* \
 && usermod -aG docker runner

USER runner
ENV RUSTUP_HOME=/home/runner/.rustup \
    CARGO_HOME=/home/runner/.cargo \
    PATH=/home/runner/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable --profile minimal \
        --component clippy --component rustfmt \
 && cargo --version && rustfmt --version && cargo clippy --version

# cargo-nextest, prebuilt from the official release feed
RUN curl -LsSf https://get.nexte.st/latest/linux \
      | tar zxf - -C /home/runner/.cargo/bin \
 && cargo nextest --version

# sccache — rustc cache. compose.yml points SCCACHE_DIR at a persistent host
# volume shared by all runner containers, so the ephemeral containers still
# share compilation results. musl build is static; pinned, bump here.
ENV SCCACHE_VERSION=v0.8.2
RUN case "$(uname -m)" in x86_64) A=x86_64;; aarch64) A=aarch64;; esac \
 && curl -fsSL "https://github.com/mozilla/sccache/releases/download/${SCCACHE_VERSION}/sccache-${SCCACHE_VERSION}-${A}-unknown-linux-musl.tar.gz" \
      | tar xz -C /tmp \
 && mv "/tmp/sccache-${SCCACHE_VERSION}-${A}-unknown-linux-musl/sccache" /home/runner/.cargo/bin/sccache \
 && rm -rf /tmp/sccache-* \
 && sccache --version

COPY --chown=runner:runner entrypoint.sh /home/runner/entrypoint.sh
RUN chmod +x /home/runner/entrypoint.sh
ENTRYPOINT ["/home/runner/entrypoint.sh"]
