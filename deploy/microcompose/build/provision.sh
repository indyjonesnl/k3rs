#!/bin/sh
# Bake: runs ONCE in a throwaway VM; context is at /mnt/microcompose-build (cwd).
# OS layer only — no kubernetes-rs binaries (sync.sh pushes those). Versions track
# containerd.Dockerfile; config.toml is staged from deploy/containerd/ by up.sh.
set -eu
CONTAINERD_VERSION="${CONTAINERD_VERSION:-2.2.4}"
CNI_VERSION="${CNI_VERSION:-1.6.2}"
ARCH=amd64

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl iptables iproute2 \
  procps conntrack crun kmod
apt-get clean; rm -rf /var/lib/apt/lists/*

curl -fsSL --retry 5 "https://github.com/containerd/containerd/releases/download/v${CONTAINERD_VERSION}/containerd-${CONTAINERD_VERSION}-linux-${ARCH}.tar.gz" | tar -xz -C /usr/local
mkdir -p /opt/cni/bin /etc/cni/net.d
curl -fsSL --retry 5 "https://github.com/containernetworking/plugins/releases/download/v${CNI_VERSION}/cni-plugins-linux-${ARCH}-v${CNI_VERSION}.tgz" | tar -xz -C /opt/cni/bin
ln -sf "$(command -v crun)" /usr/local/sbin/runc

mkdir -p /etc/containerd /etc/kubernetes-rs/pki /var/lib/kubernetes-rs
cp ./payload/containerd-config.toml /etc/containerd/config.toml
cp ./payload/units/*.service /etc/systemd/system/
printf 'overlay\nbr_netfilter\n' > /etc/modules-load.d/kubernetes-rs.conf
printf 'net.ipv4.ip_forward=1\nnet.bridge.bridge-nf-call-iptables=1\nfs.inotify.max_user_instances=1024\nfs.inotify.max_user_watches=1048576\n' > /etc/sysctl.d/90-kubernetes-rs.conf
systemctl enable containerd kubernetes-rs-hosts
