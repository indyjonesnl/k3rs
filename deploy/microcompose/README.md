# kubernetes-rs on microcompose — 3 microVMs, binary-swap dev loop

`node1` = control plane + worker (rhino/SQLite, api-server, scheduler,
controller-manager, kubelet, kube-proxy); `node2`/`node3` = kubelet + kube-proxy.
1 GiB / 2 vCPU each. Shrink `mem_limit` in `compose.yaml` once idle RSS < 512 MiB.

```bash
./up.sh                       # certs, make build-fast, bake, boot, sync
bash ../../scripts/bootstrap-cluster.sh   # CoreDNS etc. (may need adapting, see below)
# inner loop:
make build-fast ARGS="-p kubernetes-rs-kubelet --bin kubelet" && ./sync.sh kubelet
../../../microcompose/target/debug/microcompose -f compose.yaml exec node2 free -m
```

Layout: only the OS layer is baked (containerd, crun, CNI plugins, systemd units;
`build/provision.sh`). kubernetes-rs binaries are scp'd by `sync.sh` and units restarted.
Unit flags mirror `compose.sqlite.yml` / `manifests/control-plane/*.yaml`.
Pod networking: controller-manager allocates a /24 per node from 10.244.0.0/16;
kube-proxy `--configure-node-network` writes the CNI conflist and host-gw routes
(all VMs share one L2 bridge, 10.72.0.0/24).

Notes / known unknowns (not yet booted):
- Uses the release build of microcompose main (`$CARGO_TARGET_DIR/release/microcompose`); the packaged 0.1.0 is stale. YAML anchors (`<<`) are unsupported, so compose.yaml is spelled out.
- Host binaries are glibc-dynamic; Debian 13 guest glibc may be older than the host's. If
  `sync.sh` binaries fail with `GLIBC_x not found`, build musl or bake a matching toolchain.
- Debian genericcloud kernel must provide netfilter/br_netfilter/overlay; unverified.
- `bootstrap-cluster.sh` assumes docker/podman; the `kubectl apply` parts apply as-is, the
  container/static-pod parts do not. Needs a VM-mode switch.
- One project per fixed subnet at a time (10.72.0.0/24).
- Verify the guest kernel first: `microcompose exec node1 'zcat /proc/config.gz | grep -E "NF_TABLES|BRIDGE_NETFILTER|OVERLAY_FS"'`.
  If missing, microcompose direct boot (`x-vm.kernel/initramfs`) can supply a kernel; it is also the
  smallest-footprint route (see mikronetes M2a). No balloon: `mem_limit` is fixed RAM (try 400m later).
