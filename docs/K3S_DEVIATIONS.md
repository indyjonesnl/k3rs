# Deliberate deviations from k3s

kubernetes-rs is a Rust rewrite of k3s `v1.35.9+k3s1` (Kubernetes release-1.35). The
default is to port k3s and the Kubernetes it vendors faithfully. This page lists
every place kubernetes-rs deliberately does something different, and why.

**Rule for adding an entry** (CLAUDE.md, upstream-first rule 8): a deviation is
only allowed when it is deliberate, has a stated reason, and keeps the
user-visible surface (API objects, Service names and IPs, flags, config files)
compatible with k3s unless the entry says otherwise. Conformance
(Hydrophone / Sonobuoy) stays the gate for every entry.

The v1.0 target is a homelab/edge node (Raspberry Pi 3A+, aarch64, 512 MB RAM,
Kubernetes 1.35 only, single server). Idle memory is the deciding metric, so
most deviations trade a separate process or pod for an in-process Rust
component.

Status values: **shipped** (on `main`), **partial** (works in one deployment
shape only), **planned** (decided, not built), **open** (undecided or
unverified, see notes).

## Components

| Area | k3s | kubernetes-rs | Why | Status |
|---|---|---|---|---|
| Implementation language | Go | Rust | The project goal. | shipped |
| Cluster DNS | CoreDNS Deployment, `kube-dns` Service 10.96.0.10, `coredns` ConfigMap | In the all-in-one binary, `kubernetes-rs-dns` runs in-process behind the same `kube-dns` Service and ClusterIP. Multi-container compose stacks still run upstream CoreDNS as k3s ships it (`scripts/bootstrap-cluster.sh`). | Removes a pod and a Go process from the idle footprint. | partial |
| DNS forwarding | CoreDNS `forward . /etc/resolv.conf` plus `loop` | Ported from the CoreDNS plugins (`crates/dns/src/forward.rs`, #4482). Not ported: `cache`, resolv.conf reload on change, upstream TCP connection pool, DoT/DoH/DoQ. | Parity for external name resolution from ClusterFirst pods. | partial |
| CNI daemon and plugins | Flannel embedded in the agent as a library; reference CNI plugins | `flannel-rs`: the `flanneld` daemon (VXLAN, kube-subnet-manager) and the CNI plugin chain, as a separate project. | Same behaviour in Rust. Embedding it in the agent process, as k3s does, would remove one more process. | partial (separate process) |
| Network policy | kube-router's netpol controller embedded in the agent | The `NetworkPolicy` API objects are served and validated; no enforcement controller was found in the codebase. | Needed for NetworkPolicy conformance; the implementation choice (port of the kube-router controller or another Rust implementation) is not decided. | open |
| kube-router as a CNI/BGP router | not used by k3s | Not planned. | BGP routing and service proxying are not needed for a single-node homelab. | decided against |
| Container runtime | containerd plus runc | CRI v1 runtime plus `crun`. The compose stacks use stock containerd + crun today; `containerd-rs` (CRI v1, no shim, direct crun) is the Rust replacement. | Smaller footprint; CRI stays the kubelet boundary. | partial |
| Native runtime (no crun) | n/a | A single-threaded `clone3` helper behind an `OciRuntime` trait is drafted, not started. The OCI `config.json` stays the runtime boundary and CNI stays CNI. | Footprint, a second-order saving. | planned |
| Datastore | kine over SQLite by default, or embedded etcd | `rhino` (SQLite or Redis) or etcd, selectable; a kine-backed compose stack exists for conformance. | Rust implementation of the same Storage contract. | shipped |
| Cloud provider | k3s `pkg/cloudprovider`: `InstancesV2` that always reports the node as existing, `k3s://<node>` provider IDs, ServiceLB | Same shape, in Rust. The node lifecycle controller exists (#4448) but nothing starts it yet. | Parity; wiring is a follow-up. | partial |
| Bundled addons | traefik, helm-controller, metrics-server, local-path, ServiceLB, coredns | traefik, helm-controller and metrics-server run from the upstream k3s manifests. The Pi profile is intended to leave out traefik and helm-controller (the author's own node uses a Cloudflare tunnel instead). | Footprint on a 512 MB node. | partial |
| Kubelet mounts | `mount`/`umount` from the node userland | Tmpfs mounts for emptyDir and projected volumes use `mount(2)`/`umount2(2)` in-process (#4483). Other volume plugins still exec `mount`, `umount` and `systemd-run`. | Minimal node images have no util-linux. Upstream `mount-utils` execs the `mount` binary, so this differs on purpose. | partial |
| Single binary | One `k3s` binary for server and agent | One `kubernetes-rs` all-in-one binary, musl plus mimalloc in the shipped build. | Footprint; same idea as k3s. | shipped |
| Async worker threads | Go runtime: `GOMAXPROCS` = CPU count (cgroup-aware since Go 1.25); k3s sets no cap | The all-in-one binary defaults to `min(available_parallelism, 4)` tokio workers; `TOKIO_WORKER_THREADS` overrides (#4485, `docs/PERFORMANCE.md`). Standalone binaries are uncapped. | On a 24-CPU host idle anon fell from 227-240 MiB (uncapped) to 171-178 MiB; no change on a 4-CPU Pi. | shipped (all-in-one only) |

## Not deviations (still faithful)

- Kubernetes API behaviour, admission, RBAC, validation and error strings: ported
  from `../kubernetes` release-1.35.
- CRI, CNI and CSI contracts. These are not bent for any deviation above.
- `--cloud-provider=external` is the only mode; there are no in-tree cloud
  providers (as in k3s).

## Known compatibility gaps for people coming from k3s

These are places where the visible surface differs today and a k3s user could be
surprised:

- `kubernetes-rs-dns` does not read the `coredns-custom` ConfigMap, and does not cache.
  (Whether the all-in-one `kubernetes-rs-dns` handles `NodeHosts` the way k3s CoreDNS does
  has not been verified; the compose bootstrap does fill `NodeHosts` for
  CoreDNS.)
- The kubelet takes `--hostname-override`; it no longer accepts `--node-name`
  (the upstream kubelet has no such flag). The all-in-one and kube-proxy still
  accept `--node-name`.
- NetworkPolicy objects are accepted but not enforced (no enforcement controller
  found).

## Adding or changing an entry

1. Cite the k3s or Kubernetes source you are deviating from.
2. Say why, and what the memory or complexity saving is, with a measurement when
   one exists (`docs/` footprint notes).
3. State which user-visible surface stays compatible.
4. Link the PR.
