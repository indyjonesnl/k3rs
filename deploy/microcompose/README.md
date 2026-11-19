# k3rs on microcompose — 3 microVMs, one binary, token join

`node1` runs `k3rs server` (control plane on SQLite, kubelet, kube-proxy and
k3rs-dns in one process); `node2`/`node3` run
`k3rs agent --server https://node1:6443 --token-file /etc/k3rs/token`.
1 GiB / 2 vCPU each. Shrink `mem_limit` in `compose.yaml` once idle use < 512 MiB.

```bash
./up.sh            # make build-fast -p k3rs, bake (first time), boot, sync
./acceptance.sh    # 6 milestone checks + per-node `free -m`
# inner loop:
make -C ../.. build-fast ARGS="-p k3rs --bin k3rs" && ./sync.sh
KUBECONFIG=$PWD/.kubeconfig kubectl get nodes -o wide   # written by acceptance.sh
```

## Flow

1. `up.sh` builds only `-p k3rs --bin k3rs`. No `generate-certs.sh`, no rhino
   build, no `bootstrap-cluster.sh`.
2. `sync.sh` scp's the one binary to every VM and writes `/etc/k3rs/node.env`
   (`K3RS_ROLE`, `NODE_IP`, `K3RS_ARGS`), which selects the role of the single
   `k3rs.service` unit (`build/payload/units/k3rs.service`).
3. node1 starts first (`k3rs server --tls-san node1`). On first start it mints
   its PKI under `/var/lib/k3rs/tls/` and the join token at
   **`/var/lib/k3rs/token`** (`node-token`/`agent-token` symlink to it).
4. `sync.sh` waits for the token over ssh, writes it to `/etc/k3rs/token`
   (0600) on node2/node3 and starts their agents. Agents pin the server CA from
   the token, fetch their own certs, and write kubeconfigs under
   `/var/lib/k3rs/agent/`. No certs are copied by hand.
5. `node1` resolves through the peers block microcompose writes into each
   VM's `/etc/hosts`; the serving cert carries `node1`, the node IPs,
   `localhost` and `127.0.0.1`, so the host uses the forwarded
   `https://127.0.0.1:6443`.

Admin kubeconfig: `node1:/var/lib/k3rs/tls/admin.kubeconfig` (server
`https://127.0.0.1:6443`); `acceptance.sh` copies it to `./.kubeconfig`.
The server runs with `--skip-auth` (milestone 1): anything that reaches
:6443 is cluster-admin.

Pod networking: node IPAM gives each node a /24 of 10.244.0.0/16; the
in-process node-network agent writes `/etc/cni/net.d/10-k3rs.conflist` and
host-gw routes (all VMs share one L2 bridge, 10.72.0.0/24). DNS: k3rs-dns on
node1 binds `10.72.0.2:53` (not `0.0.0.0`: systemd-resolved owns
127.0.0.53/54:53 in the guest); `kube-dns` 10.96.0.10 points at it.
`kubectl exec`/`attach`/`port-forward`: the kubelet proxies to containerd's
CRI stream server on the same VM (`CONTAINERD_STREAM_HOST=127.0.0.1`, port
10010, set in `k3rs.service`).

## acceptance.sh

Exits non-zero on the first failing check: (1) 3 nodes Ready within 3 min,
(2) distinct `spec.podCIDR`s, (3) kube-dns has an endpoint, (4) busybox pinned
on node2 and node3 Running, (5) `kubectl exec` nslookup of
`kubernetes.default.svc.cluster.local` via 10.96.0.10 from the node2 pod,
(6) `kubectl exec` wget from the node2 pod to an nginx pod IP on node3. Test
pods (`acc-*` in `default`) are recreated per run and left running. Images
are pulled from Docker Hub (the VMs have outbound access); override with
`BUSYBOX_IMAGE` / `NGINX_IMAGE`.

## Memory baseline (2026-11-19, 3 acc-* pods running, `free -m` used)

| node | used / total MiB | k3rs RSS | containerd RSS |
|---|---|---|---|
| node1 (server) | 299 / 964 | 163 | 49 |
| node2 (agent)  | 264 / 964 | 51  | 63 |
| node3 (agent)  | 307 / 964 | 51  | 74 |

## Notes

- Uses the release build of microcompose main (`$CARGO_TARGET_DIR/release/microcompose`);
  the packaged 0.1.0 is stale. YAML anchors (`<<`) are unsupported, so compose.yaml is spelled out.
- The host-built glibc binary needs GLIBC_2.39; the Debian 13 guest has 2.41.
- Changing anything under `build/` (units, provision.sh) re-bakes the image on
  the next `up` (~1.2 GB in `~/.cache/microcompose/derived`).
- One project per fixed subnet at a time (10.72.0.0/24). Start clean with
  `microcompose -f compose.yaml destroy`.
