#!/usr/bin/env bash
# Milestone-1 acceptance for the token-join rig (node1 = k3rs server,
# node2/node3 = k3rs agent). Exits non-zero on the FIRST failing check.
#   1. 3 nodes Ready (within READY_TIMEOUT, default 180s)
#   2. every node has spec.podCIDR, all distinct
#   3. kube-dns Service has an endpoint
#   4. busybox pinned (nodeName) on node2 and node3 each Running
#   5. node2 pod: nslookup kubernetes.default.svc.cluster.local 10.96.0.10 answers
#   6. node2 pod can wget an nginx pod's IP on node3
# Then prints per-node `free -m` used memory (baseline for the < 512 MiB goal).
# Test pods (acc-*) in `default` are deleted at the start and left running.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

READY_TIMEOUT="${READY_TIMEOUT:-180}"
POD_TIMEOUT="${POD_TIMEOUT:-300}"
BUSYBOX_IMAGE="${BUSYBOX_IMAGE:-docker.io/library/busybox:1.36}"
NGINX_IMAGE="${NGINX_IMAGE:-docker.io/library/nginx:1.27-alpine}"
NS=default
export KUBECONFIG="$HERE/.kubeconfig"

pass() { echo "PASS [$1] $2"; }
fail() {
  echo "FAIL [$1] $2" >&2
  shift 2
  [ $# -gt 0 ] && printf '%s\n' "$@" >&2
  exit 1
}
k() { kubectl --request-timeout=20s "$@"; }

# wait_for <seconds> <description> <cmd...>: poll cmd every 3s.
wait_for() {
  local t=$1 what=$2; shift 2
  local deadline=$((SECONDS + t))
  until "$@" >/dev/null 2>&1; do
    [ $SECONDS -lt $deadline ] || return 1
    sleep 3
  done
}

# --- kubeconfig from node1 (server already 127.0.0.1:6443; forced anyway) ---
nssh "$CP" 'sudo cat /var/lib/k3rs/tls/admin.kubeconfig' > "$KUBECONFIG.tmp" \
  || fail 0 "could not read $CP:/var/lib/k3rs/tls/admin.kubeconfig (is k3rs server up? ./sync.sh)"
sed -E 's#(server: )https://[^ ]+#\1https://127.0.0.1:6443#' "$KUBECONFIG.tmp" > "$KUBECONFIG"
rm -f "$KUBECONFIG.tmp"; chmod 600 "$KUBECONFIG"
echo "KUBECONFIG=$KUBECONFIG"

# --- 1. three nodes Ready -------------------------------------------------
ready_count() {
  k get nodes -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}' \
    | awk '$2=="True"' | wc -l
}
three_ready() { [ "$(ready_count)" -ge 3 ]; }
if wait_for "$READY_TIMEOUT" "3 nodes Ready" three_ready; then
  pass 1 "3 nodes Ready"; k get nodes -o wide
else
  fail 1 "fewer than 3 nodes Ready after ${READY_TIMEOUT}s" "$(k get nodes -o wide 2>&1)"
fi

# --- 2. distinct podCIDRs -------------------------------------------------
cidrs="$(k get nodes -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.spec.podCIDR}{"\n"}{end}')"
n_set="$(awk 'NF==2' <<<"$cidrs" | wc -l)"
n_uniq="$(awk 'NF==2{print $2}' <<<"$cidrs" | sort -u | wc -l)"
[ "$n_set" -eq 3 ] && [ "$n_uniq" -eq 3 ] \
  || fail 2 "expected 3 nodes with distinct spec.podCIDR (set=$n_set distinct=$n_uniq)" "$cidrs"
pass 2 "podCIDRs: $(tr '\n' ' ' <<<"$cidrs")"

# --- 3. kube-dns has an endpoint -----------------------------------------
dns_eps() {
  k -n kube-system get endpointslices -l kubernetes.io/service-name=kube-dns \
    -o jsonpath='{range .items[*].endpoints[*]}{.addresses[0]}{" "}{end}'
}
has_dns_ep() { [ -n "$(dns_eps | tr -d ' ')" ]; }
k -n kube-system get svc kube-dns >/dev/null 2>&1 || fail 3 "Service kube-system/kube-dns not found"
wait_for 60 "kube-dns endpoint" has_dns_ep \
  || fail 3 "kube-dns has no EndpointSlice address after 60s" "$(k -n kube-system get svc,endpointslices -o wide 2>&1)"
pass 3 "kube-dns endpoints: $(dns_eps)"

# --- 4. busybox pinned on node2 and node3 ---------------------------------
k -n $NS delete pod acc-bb-node2 acc-bb-node3 acc-nginx-node3 --ignore-not-found --wait=true --timeout=90s >/dev/null 2>&1 || true
pod_yaml() { # name node image [command-json]
  cat <<EOF
apiVersion: v1
kind: Pod
metadata: { name: $1, namespace: $NS, labels: { app: k3rs-acceptance } }
spec:
  nodeName: $2
  terminationGracePeriodSeconds: 1
  containers:
  - name: main
    image: $3
${4:+    command: $4}
EOF
}
pod_yaml acc-bb-node2 node2 "$BUSYBOX_IMAGE" '["sleep","86400"]' | k apply -f - >/dev/null || fail 4 "create acc-bb-node2"
pod_yaml acc-bb-node3 node3 "$BUSYBOX_IMAGE" '["sleep","86400"]' | k apply -f - >/dev/null || fail 4 "create acc-bb-node3"
pod_yaml acc-nginx-node3 node3 "$NGINX_IMAGE" | k apply -f - >/dev/null || fail 4 "create acc-nginx-node3"
running() { [ "$(k -n $NS get pod "$1" -o jsonpath='{.status.phase}')" = Running ]; }
for p in acc-bb-node2 acc-bb-node3; do
  wait_for "$POD_TIMEOUT" "$p Running" running "$p" \
    || fail 4 "$p not Running after ${POD_TIMEOUT}s" "$(k -n $NS get pod "$p" -o wide 2>&1)" \
         "$(k -n $NS get pod "$p" -o jsonpath='{.status}' 2>&1)" "$(k -n $NS get events 2>&1 | tail -15)"
done
pass 4 "busybox Running on node2 and node3"; k -n $NS get pods -o wide

# --- 5. DNS from the node2 pod --------------------------------------------
out="$(k -n $NS exec acc-bb-node2 -- nslookup kubernetes.default.svc.cluster.local 10.96.0.10 2>&1)" || true
kip="$(k -n default get svc kubernetes -o jsonpath='{.spec.clusterIP}')"
grep -Eq "Address:?[[:space:]]+$kip\$" <<<"$out" \
  || fail 5 "nslookup kubernetes.default.svc.cluster.local via 10.96.0.10 did not return $kip" "$out"
pass 5 "nslookup -> $kip"; echo "$out"

# --- 6. node2 pod -> nginx pod IP on node3 --------------------------------
wait_for "$POD_TIMEOUT" "acc-nginx-node3 Running" running acc-nginx-node3 \
  || fail 6 "acc-nginx-node3 not Running after ${POD_TIMEOUT}s" "$(k -n $NS get pod acc-nginx-node3 -o wide 2>&1)"
nip="$(k -n $NS get pod acc-nginx-node3 -o jsonpath='{.status.podIP}')"
[ -n "$nip" ] || fail 6 "acc-nginx-node3 has no podIP"
out="$(k -n $NS exec acc-bb-node2 -- wget -qO- -T 5 "http://$nip/" 2>&1)" || true
grep -q "Welcome to nginx" <<<"$out" || fail 6 "wget http://$nip/ from acc-bb-node2 (node2) failed" "$out"
pass 6 "node2 pod -> nginx $nip on node3"

echo "ALL 6 CHECKS PASSED"
echo "--- per-node memory (free -m, used MiB) ---"
for n in "${NODES[@]}"; do
  echo "$n: $(nssh "$n" "free -m | awk '/^Mem:/{print \$3\" used / \"\$2\" total\"}'") MiB"
done
