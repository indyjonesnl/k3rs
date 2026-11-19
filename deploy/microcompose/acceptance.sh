#!/usr/bin/env bash
# Acceptance for the token-join rig (node1 = k3rs server, node2/node3 =
# k3rs agent). Checks 1-6 build on each other and exit non-zero on the FIRST
# failure:
#   1. 3 nodes Ready (within READY_TIMEOUT, default 180s)
#   2. every node has spec.podCIDR, all distinct
#   3. kube-dns Service has an endpoint
#   4. busybox pinned (nodeName) on node2 and node3 each Running
#   5. node2 pod: nslookup kubernetes.default.svc.cluster.local 10.96.0.10 answers
#   6. node2 pod can wget an nginx pod's IP on node3
# Security posture (all run; the script exits non-zero if any failed). The
# curls run on node2, so `node1`/`node3` resolve and node2's own kubelet
# client cert (/var/lib/k3rs/agent/client-kubelet.{crt,key},
# CN system:node:node2, O system:nodes) is at hand:
#   7. anonymous_api_401: no client cert -> :6443 /api and /healthz are 401
#      (k3s anonymous-auth=false, pkg/daemons/control/server.go:222)
#   8. anonymous_supervisor_ok: /cacerts and /ping still 200 without a cert
#      (k3s supervisor routes are outside kube-apiserver authn)
#   9. node_cert_cannot_read_secrets: node2 cert reads its own Node (200)
#      but listing kube-system Secrets is 403
#  10. node_cert_cannot_read_other_node_password: node2 cert GET
#      kube-system/node3.node-password.k3rs is 403 (the Secret exists)
#  11. anonymous_kubelet_rejected: no client cert -> node2:10250 and
#      node1:10250 /pods are 401 (kubelet anonymous-auth=false, k3s
#      pkg/daemons/agent/agent.go)
#  12. node_cert_cannot_exec_other_node: node2 cert -> node3:10250 /pods and
#      POST /exec are 403 (kubelet SubjectAccessReview on nodes/proxy)
#  13. exec_via_apiserver_works: kubectl exec + logs reach node3's kubelet
#      through the api-server proxy (system:apiserver client cert)
#  14. no_forbidden_flood: after a STEADY_WINDOW (default 60s) of idling,
#      no `403`/`Forbidden` journal lines on any node, except lines matching
#      FORBIDDEN_ALLOW (the deferred set; counts are always printed). The
#      server logs every denied request at debug (`Forbidden uri=...`,
#      upstream filters/authorization.go:93); sync.sh turns that target on.
# Then prints per-node `free -m` used memory and k3rs/containerd RSS.
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
KC_TMP="$(mktemp "$HERE/.kubeconfig.tmp.XXXXXX")"   # holds admin creds: never left behind
trap 'rm -f "$KC_TMP"' EXIT
chmod 600 "$KC_TMP"
nssh "$CP" 'sudo cat /var/lib/k3rs/tls/admin.kubeconfig' > "$KC_TMP" \
  || fail 0 "could not read $CP:/var/lib/k3rs/tls/admin.kubeconfig (is k3rs server up? ./sync.sh)"
sed -E 's#(server: )https://[^ ]+#\1https://127.0.0.1:6443#' "$KC_TMP" > "$KUBECONFIG"
chmod 600 "$KUBECONFIG"
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

echo "CHECKS 1-6 PASSED"

# --- security posture (7-14): every check runs, failures are collected ----
FAILED=()
sfail() {
  local id=$1; echo "FAIL [$1] $2" >&2; shift 2
  [ $# -gt 0 ] && printf '%s\n' "$@" >&2
  FAILED+=("$id")
}
AGENT_CERT=/var/lib/k3rs/agent/client-kubelet.crt
AGENT_KEY=/var/lib/k3rs/agent/client-kubelet.key
# code <node> <curl args...>: HTTP status of a curl run on <node> (as root, so
# the 0600 agent key is readable). 000 = no HTTP response.
code() {
  local n=$1; shift
  nssh "$n" "sudo curl -sk -o /dev/null -m 10 -w '%{http_code}' $*" 2>/dev/null || true
}
# expect <check> <want> <got> <what>
expect() {
  if [ "$3" = "$2" ]; then pass "$1" "$4 -> $3"; else sfail "$1" "$4 -> $3 (want $2)"; fi
}
NODE_CERT="--cert $AGENT_CERT --key $AGENT_KEY"

# 7. anonymous API requests are 401
for path in /api /healthz; do
  expect 7 401 "$(code node2 "https://$CP:6443$path")" "anonymous_api_401 GET $path"
done
# 8. supervisor routes stay anonymous
for path in /cacerts /ping; do
  expect 8 200 "$(code node2 "https://$CP:6443$path")" "anonymous_supervisor_ok GET $path"
done
# 9. node cert authenticates (own Node 200) but cannot read Secrets
expect 9 200 "$(code node2 "$NODE_CERT https://$CP:6443/api/v1/nodes/node2")" \
  "node_cert_cannot_read_secrets (control) node2 cert GET nodes/node2"
expect 9 403 "$(code node2 "$NODE_CERT https://$CP:6443/api/v1/namespaces/kube-system/secrets")" \
  "node_cert_cannot_read_secrets node2 cert LIST kube-system secrets"
# 10. not another node's password Secret (which must exist for this to mean anything)
k -n kube-system get secret node3.node-password.k3rs >/dev/null 2>&1 \
  || sfail 10 "node_cert_cannot_read_other_node_password: kube-system/node3.node-password.k3rs does not exist"
expect 10 403 "$(code node2 "$NODE_CERT https://$CP:6443/api/v1/namespaces/kube-system/secrets/node3.node-password.k3rs")" \
  "node_cert_cannot_read_other_node_password node2 cert GET node3.node-password.k3rs"
# 11. anonymous kubelet API is 401
for n in node2 "$CP"; do
  expect 11 401 "$(code node2 "https://$n:10250/pods")" "anonymous_kubelet_rejected GET $n:10250/pods"
done
# 12. a node cert is not authorized on another node's kubelet
expect 12 403 "$(code node2 "$NODE_CERT https://node3:10250/pods")" \
  "node_cert_cannot_exec_other_node node2 cert GET node3:10250/pods"
expect 12 403 "$(code node2 "$NODE_CERT -X POST 'https://node3:10250/exec/$NS/acc-bb-node3/main?command=true&output=1'")" \
  "node_cert_cannot_exec_other_node node2 cert POST node3:10250/exec"
# 13. exec and logs through the api-server proxy (node3 kubelet)
out="$(k -n $NS exec acc-bb-node3 -- echo exec-ok 2>&1)" || true
[ "$out" = exec-ok ] && pass 13 "exec_via_apiserver_works kubectl exec acc-bb-node3 (node3)" \
  || sfail 13 "exec_via_apiserver_works kubectl exec acc-bb-node3" "$out"
out="$(k -n $NS logs acc-nginx-node3 --tail=50 2>&1)" || true
grep -q 'GET / HTTP' <<<"$out" && pass 13 "exec_via_apiserver_works kubectl logs acc-nginx-node3 shows check 6's request" \
  || sfail 13 "exec_via_apiserver_works kubectl logs acc-nginx-node3" "$out"

# 14. no 403 flood from the embedded identities in steady state
STEADY_WINDOW="${STEADY_WINDOW:-60}"
# Deferred (documented in README): the Service and APIServiceAvailability
# controllers have no upstream role (upstream does that work inside
# kube-apiserver) and their periodic live GETs as system:kube-controller-manager
# are denied; ClusterIP/NodePort allocation and APIService availability are
# done by the api-server itself, so nothing breaks. Pass FORBIDDEN_ALLOW='^$'
# to count them as failures.
FORBIDDEN_ALLOW="${FORBIDDEN_ALLOW:-uri=/api/v1/namespaces/[^/ ]+/services/[^/ ?]+ |uri=/apis/apiregistration\.k8s\.io/v1/apiservices/}"
since="$(nssh "$CP" 'date +%s')"
echo "idling ${STEADY_WINDOW}s for the steady-state log scan (since @$since)"
sleep "$STEADY_WINDOW"
total=0
for n in "${NODES[@]}"; do
  lines="$(nssh "$n" "sudo journalctl -u k3rs --no-pager -o cat --since @$since" 2>/dev/null \
    | sed -E 's/\x1b\[[0-9;]*m//g' | grep -Ei '(\b403\b|forbidden)' || true)"
  all=$(grep -c . <<<"$lines" || true)
  if [ -n "$FORBIDDEN_ALLOW" ]; then
    left="$(grep -Ev "$FORBIDDEN_ALLOW" <<<"$lines" || true)"
  else
    left="$lines"
  fi
  bad=$(grep -c . <<<"$left" || true)
  echo "$n: $all 403/Forbidden lines in ${STEADY_WINDOW}s ($bad not in FORBIDDEN_ALLOW)"
  # distinct messages, numbers/uids/timestamps stripped
  [ "$all" -gt 0 ] && sed -E 's/^[^ ]+ +//; s/ThreadId\([0-9]+\)//; s/[0-9a-f-]{36}//g' <<<"$lines" | sort | uniq -c | sort -rn | head -15
  total=$((total + bad))
done
[ "$total" -eq 0 ] && pass 14 "no_forbidden_flood: 0 unexpected 403/Forbidden lines" \
  || sfail 14 "no_forbidden_flood: $total unexpected 403/Forbidden lines"

echo "--- per-node memory (free -m used; RSS MiB) ---"
for n in "${NODES[@]}"; do
  echo "$n: $(nssh "$n" "free -m | awk '/^Mem:/{print \$3\" used / \"\$2\" total\"}'; \
    for p in k3rs containerd; do printf ' %s=%s' \$p \$(ps -C \$p -o rss= | awk '{s+=\$1} END {print int(s/1024)}'); done") MiB"
done

if [ ${#FAILED[@]} -gt 0 ]; then
  echo "FAILED security checks: ${FAILED[*]}" >&2
  exit 1
fi
echo "ALL 14 CHECKS PASSED"
