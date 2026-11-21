# k3rs on microcompose — 3 microVMs, one binary, token join

`node1` runs `k3rs server` (control plane on SQLite, kubelet, kube-proxy and
k3rs-dns in one process); `node2`/`node3` run
`k3rs agent --server https://node1:6443 --token-file /etc/k3rs/token`.
1 GiB / 2 vCPU each. Shrink `mem_limit` in `compose.yaml` once idle use < 512 MiB.

```bash
./up.sh            # make build-fast -p k3rs, bake (first time), boot, sync
./acceptance.sh    # 18 checks (cluster + authn/RBAC posture) + per-node memory
# inner loop:
make -C ../.. build-fast ARGS="-p k3rs --bin k3rs" && ./sync.sh
KUBECONFIG=$PWD/.kubeconfig kubectl get nodes -o wide   # written by acceptance.sh
```

## Flow

1. `up.sh` builds only `-p k3rs --bin k3rs`. No `generate-certs.sh`, no rhino
   build, no `bootstrap-cluster.sh`.
2. `sync.sh` scp's the one binary to every VM and writes `/etc/k3rs/node.env`
   (`K3RS_ROLE`, `NODE_IP`, `K3RS_ARGS`; on node1 also
   `RUST_LOG=info,k3rs_api_server::authorization_filter=debug,k3rs_kubelet::server_auth=debug`,
   on agents `RUST_LOG=info,k3rs_kubelet::server_auth=debug`, so every
   denied request is logged), which selects the role of the single
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
`https://127.0.0.1:6443`, client cert CN `system:admin` / O `system:masters`);
`acceptance.sh` copies it to `./.kubeconfig` (0600, gitignored).

## Security posture

Like k3s (`pkg/daemons/control/server.go` `apiServer`, `pkg/daemons/agent/agent.go`):

- **api-server :6443**: x509 client certs against the client CA,
  `--authorization-mode Node,RBAC`, `--anonymous-auth=false`. Any request
  without a valid credential is 401, `/healthz`, `/readyz`, `/version` and
  `/metrics` included. Only the supervisor routes (`/cacerts`, `/ping`, and
  `/v1-k3rs/*` behind the join token) answer without a client cert.
- **Embedded components** each present their own minted cert
  (`<data-dir>/tls/client-*.{crt,key}`, `<data-dir>/cred/*.kubeconfig`):
  `system:kube-scheduler`, `system:kube-controller-manager` (informer reads)
  plus one `system:serviceaccount:kube-system:<controller>` identity per
  controller (k3s `use-service-account-credentials`; the k3rs-only Events
  controller as `kube-system/event-gc-controller` with the k3rs ClusterRole
  `system:k3rs-event-gc`, core `events` only), `system:k3rs-dns`,
  `system:kube-proxy`, `system:node:<node>`. Agents fetch their kubelet /
  kube-proxy certs with the join token into `/var/lib/k3rs/agent/`.
- **kube-proxy** (`system:kube-proxy`, seeded `system:node-proxier`, no Pod
  access): on k3rs server/agent nodes only, hostPorts are left to the node
  conflist's CNI `portmap` plugin (as k3s), so it lists/watches no Pods. The
  standalone kube-proxy (compose/conformance stacks) and the bare all-in-one
  keep KUBE-HOSTPORTS unchanged.
- **kubelet :10250** on every node: TLS with the node's `serving-kubelet`
  cert, anonymous off, x509 against the client CA, authorization by
  SubjectAccessReview (`nodes/proxy` etc.). The api-server reaches it for
  `exec`/`logs`/`attach`/`port-forward` (and `nodes/<n>/proxy` on the kubelet
  port) as `system:apiserver`, and verifies the kubelet's serving cert against
  the server CA for the node IP it dials (k3s
  `kubelet-certificate-authority`; `--insecure-skip-tls-verify-backend` on
  `kubectl logs` skips it, as upstream).
- **Legacy ServiceAccount token Secrets** are signed by the tokens controller
  with the api-server's own signing key (`sa.key`, ECDSA P-256 -> ES256; k3s
  passes `service-account-private-key-file` = the signing key) and
  authenticate.
- **k3rs-managed RBAC** (`system:k3rs-dns`, `system:k3rs-event-gc` and their
  bindings) carries `rbac.authorization.kubernetes.io/autoupdate: "true"` and
  is reconciled on every server start like the upstream bootstrap policy
  (missing rules/subjects added, extra ones kept, `"false"` opts out).
- Every 401 is a `Status` object (`reason: Unauthorized`), negotiated per
  `Accept`.
- The join token is still printed in the server's journal (k3s does the
  same); treat `journalctl -u k3rs` on node1 as secret.

`acceptance.sh` checks 7-18 prove each of these on the running rig (see
below); readiness is probed with the admin cert or the supervisor `/ping`,
never anonymously.

Pod networking: node IPAM gives each node a /24 of 10.244.0.0/16; the
in-process node-network agent writes `/etc/cni/net.d/10-k3rs.conflist` and
host-gw routes (all VMs share one L2 bridge, 10.72.0.0/24). DNS: k3rs-dns on
node1 binds `10.72.0.2:53` (not `0.0.0.0`: systemd-resolved owns
127.0.0.53/54:53 in the guest); `kube-dns` 10.96.0.10 points at it, and it
forwards non-cluster names to the guest's `/etc/resolv.conf` (CoreDNS
`forward`, #4482). The multi-container stacks run upstream CoreDNS from the
k3s manifest instead (#4473); `k3rs server`, like the all-in-one, keeps the
in-process k3rs-dns under its own identity `system:k3rs-dns` (narrower than
k3s `system:coredns`, which also lists endpoints and namespaces).
`kubectl exec`/`attach`/`port-forward`: the kubelet proxies to containerd's
CRI stream server on the same VM (`CONTAINERD_STREAM_HOST=127.0.0.1`, port
10010, set in `k3rs.service`).

## acceptance.sh

Checks 1-6 exit non-zero on the first failure: (1) 3 nodes Ready within
3 min, (2) distinct `spec.podCIDR`s, (3) kube-dns has an endpoint,
(4) busybox pinned on node2 and node3 Running, (5) `kubectl exec` nslookup of
`kubernetes.default.svc.cluster.local` via 10.96.0.10 from the node2 pod, and
of an external name (`EXTERNAL_NAME`, default `dns.google`) forwarded upstream,
(6) `kubectl exec` wget from the node2 pod to an nginx pod IP on node3.
Checks 7-18 all run (non-zero exit if any failed); the curls run on node2
with and without node2's own kubelet client cert
(`/var/lib/k3rs/agent/client-kubelet.{crt,key}`):
(7) anonymous `/api`, `/healthz` -> 401; (8) anonymous `/cacerts`, `/ping`
-> 200; (9) node2 cert: own Node 200, kube-system Secrets 403; (10) node2
cert: `node3.node-password.k3rs` 403; (11) anonymous node2/node1 `:10250/pods`
-> 401; (12) node2 cert on node3's kubelet `/pods` and `POST /exec` -> 403;
(13) `kubectl exec` and `kubectl logs` through the api-server into node3;
(14) after `STEADY_WINDOW` (60 s) idle, no `403`/`Forbidden` line in any
node's `journalctl -u k3rs` (except `FORBIDDEN_ALLOW`, a regex; counts are
printed); it fails if a journal cannot be read or is empty, and unless the
deliberate denials of checks 9, 10 (node1) and 12 (node3's kubelet) are in
the journals (positive control). Run it on a rig older than 1 h too: Events
then age out and the Events controller's cleanup is exercised. (15) node3's kubelet serving
cert verifies against the server CA for node3's IP (`openssl s_client` on
node1), and a rogue kubelet (self-signed cert with node3's SANs, `openssl
s_server` on node3 behind a short-lived iptables REDIRECT of node1's
connections to :10250) is refused by `kubectl logs`, reached only with
`--insecure-skip-tls-verify-backend`; logs work again afterwards. (16)
`system:k3rs-dns`/`system:k3rs-event-gc` roles and bindings carry
`autoupdate=true` and DNS can watch EndpointSlices. (17) a
`kubernetes.io/service-account-token` Secret for `acc-legacy` gets a token
that authenticates (SelfSubjectReview username). (18) a bad bearer token gets
a 401 `Status` JSON. Then `free -m` and k3rs/containerd RSS per node. Test pods
(`acc-*` in `default`) are recreated per run and left running. Images are
pulled from Docker Hub (the VMs have outbound access); override with
`BUSYBOX_IMAGE` / `NGINX_IMAGE`.

## Memory (2026-11-19, `free -m` used, 3 acc-* pods running)

| node | milestone 1 (`--skip-auth`) used / k3rs RSS | authn + RBAC used / k3rs RSS | containerd RSS |
|---|---|---|---|
| node1 (server) | 299 / 163 | 315 / 178 | 48 |
| node2 (agent)  | 264 / 51  | 262 / 52  | 63 |
| node3 (agent)  | 307 / 51  | 287 / 53  | 73 |

Of 964 MiB per VM. The server's +15 MiB is mostly the per-identity TLS client
pools (one write client per controller identity, ~5 MiB) and the kubelet's
authenticated API.

## Known 403s in steady state (deferred)

`acceptance.sh` check 14 allows exactly these (about 0.8/s on node1):
the k3rs-only Service and APIServiceAvailability controllers re-read Services
and APIServices with live GETs as `system:kube-controller-manager`, which has
list/watch but not get on them. Upstream does that work inside kube-apiserver;
here the api-server already allocates ClusterIPs/NodePorts at create and marks
local APIServices Available, so nothing is lost.

## Known functional gaps in server mode

Controllers with no upstream ServiceAccount are unmapped
(`crates/controller-manager/src/identities.rs`) and run as
`system:kube-controller-manager`, which can list/watch but not write what they
manage:

- `type: LoadBalancer` Services stay `<pending>`: the LoadBalancer (ServiceLB)
  controller is unmapped (k3s runs it in its cloud-controller-manager) and
  cannot write Service status or its DaemonSets.
- The other unmapped addon controllers do not take effect either: CSIAttacher,
  VolumeSnapshot, StorageClass, VerticalPodAutoscaler, NetworkPolicy, Ingress,
  PriorityClass, Service and APIServiceAvailability (the last two are covered
  by the api-server, see above).
- `kubectl exec` over WebSocket falls back to SPDY.
- The bundled addons main runs on the multi-container stacks from
  `scripts/bootstrap-cluster.sh` (upstream CoreDNS #4473, local-path-provisioner
  #4475, metrics-server #4476, traefik via helm-controller #4480) are not
  deployed by `k3rs server`: the binary has no addon/manifest bootstrap yet
  (k3s applies them with its deploy controller from `server/manifests`). Their
  RBAC ships inside those manifests, so nothing is seeded for them here. In
  their place: in-process k3rs-dns, and the api-server's seeded `standard`
  StorageClass (k3rs.io/hostpath).
- The cloud-provider node lifecycle controller (#4448) is a library only;
  nothing starts it, so it has no identity in
  `crates/controller-manager/src/identities.rs`. When it is started it should
  run like k3s' embedded cloud-controller-manager
  (User + ClusterRole `k3s-cloud-controller-manager`, k3s
  `manifests/ccm.yaml`; started from `pkg/daemons/control/server.go`).

## Notes

- Uses the release build of microcompose main (`$CARGO_TARGET_DIR/release/microcompose`);
  the packaged 0.1.0 is stale. YAML anchors (`<<`) are unsupported, so compose.yaml is spelled out.
- The host-built glibc binary needs GLIBC_2.39; the Debian 13 guest has 2.41.
- Changing anything under `build/` (units, provision.sh) re-bakes the image on
  the next `up` (~1.2 GB in `~/.cache/microcompose/derived`).
- One project per fixed subnet at a time (10.72.0.0/24). Start clean with
  `microcompose -f compose.yaml destroy`.
