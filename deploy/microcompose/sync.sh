#!/usr/bin/env bash
# Push binaries + certs into the running VMs and (re)start units. Idempotent;
# this is the inner dev loop:  make build-fast ARGS="-p kubernetes-rs-kubelet --bin kubelet" && ./sync.sh
# usage: ./sync.sh [binary...]   (default: every binary that exists in $BIN_DIR)
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

CP_BINS=(rhino-server api-server scheduler controller-manager)
ALL_BINS=(kubelet kube-proxy)
want=("$@"); [ ${#want[@]} -gt 0 ] || want=("${CP_BINS[@]}" "${ALL_BINS[@]}")
CERTS="$ROOT/.kubernetes-rs/certs"
RHINO_BIN="${RHINO_BIN:-$HERE/dist/bin/rhino-server}"

src_of() { [ "$1" = rhino-server ] && echo "$RHINO_BIN" || echo "$BIN_DIR/$1"; }
unit_of() { case $1 in rhino-server) echo kubernetes-rs-rhino;; *) echo "kubernetes-rs-$1";; esac; }

for n in "${NODES[@]}"; do
  ip="$(node_ip "$n")"
  until nssh "$n" true 2>/dev/null; do echo "waiting for ssh on $n"; sleep 3; done
  nssh "$n" 'cloud-init status --wait >/dev/null 2>&1 || true'
  if [ "$n" = "$CP" ]; then bins=("${CP_BINS[@]}" "${ALL_BINS[@]}"); else bins=("${ALL_BINS[@]}"); fi

  stage=(); units=()
  for b in "${bins[@]}"; do
    [[ " ${want[*]} " == *" $b "* ]] || continue
    s="$(src_of "$b")"; [ -x "$s" ] || { echo "skip $b on $n: $s missing" >&2; continue; }
    stage+=("$s"); units+=("$(unit_of "$b")")
  done
  # Certs/kubeconfigs: embedded-CA kubeconfigs, so a flat copy is enough.
  nscp "$n" "$CERTS"/*.crt "$CERTS"/*.key "$CERTS"/*.conf "$CERTS"/sa.pub ${stage[@]+"${stage[@]}"} >/dev/null
  nssh "$n" "sudo sh -s" <<REMOTE
set -e
mkdir -p /etc/kubernetes-rs/pki
cd /tmp
mv -f *.crt *.key *.conf sa.pub /etc/kubernetes-rs/pki/ 2>/dev/null || true
chmod 600 /etc/kubernetes-rs/pki/*.key
grep -q ' api-server\$' /etc/hosts || echo '10.72.0.2 api-server' >> /etc/hosts
echo 'NODE_IP=$ip' > /etc/kubernetes-rs/node.env
for f in ${stage[@]+"${stage[@]##*/}"}; do install -m755 /tmp/\$f /usr/local/bin/\$f; rm -f /tmp/\$f; done
systemctl daemon-reload
# Control-plane units only exist on node1; every node runs kubelet + kube-proxy.
for u in ${units[@]+"${units[@]}"}; do
  case \$u in kubernetes-rs-rhino|kubernetes-rs-api-server|kubernetes-rs-scheduler|kubernetes-rs-controller-manager) [ "\$(hostname)" = $CP ] || continue;; esac
  systemctl enable \$u >/dev/null 2>&1; systemctl restart \$u
done
REMOTE
  echo "$n: synced ${units[*]:-nothing}"
done
