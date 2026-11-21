#!/usr/bin/env bash
# Acceptance for the token-join rig (node1 = k3rs server, node2/node3 =
# k3rs agent). Checks 1-6 build on each other and exit non-zero on the FIRST
# failure:
#   1. 3 nodes Ready (within READY_TIMEOUT, default 180s)
#   2. every node has spec.podCIDR, all distinct
#   3. kube-dns Service has an endpoint
#   4. busybox pinned (nodeName) on node2 and node3 each Running
#   5. node2 pod: nslookup kubernetes.default.svc.cluster.local 10.96.0.10 answers,
#      and an external name (EXTERNAL_NAME, default dns.google) is forwarded
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
#      upstream filters/authorization.go:93) and every kubelet logs its
#      denials at debug (`Forbidden user=...`); sync.sh turns both on. The
#      check fails when a journal cannot be read or is empty, and unless the
#      deliberate denials of checks 9, 10 and 12 are found (positive control).
#  15. kubelet_serving_cert_verified: node2's and node3's kubelet serving
#      certs verify against the server CA for each node's registered
#      InternalIP (k3s kubelet-certificate-authority
#      = server CA, pkg/daemons/control/server.go:248); a rogue "kubelet"
#      (self-signed cert for node3's IP, `openssl s_server` behind a brief
#      iptables REDIRECT of node1 -> node3:10250) is refused by the
#      api-server for `kubectl logs`, reached only with
#      --insecure-skip-tls-verify-backend, and logs work again afterwards
#  16. k3rs_rbac_reconciled: system:k3rs-dns / system:k3rs-event-gc carry
#      autoupdate=true and the current rules (bootstrap RBAC reconcile)
#  17. legacy_sa_token_authenticates: a kubernetes.io/service-account-token
#      Secret gets a token (signed with the server's ECDSA sa.key) that
#      authenticates (SelfSubjectReview username)
#  18. unauthorized_is_status: a bad bearer token gets a 401 `Status` JSON
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
# One cleanup for every exit path (normal, fail, ^C, kill): the admin-creds
# temp file and, once check 15 started it, the rogue kubelet on node3.
ROGUE_STARTED=0
cleanup() {
  rm -f "$KC_TMP"
  [ "$ROGUE_STARTED" = 1 ] && rogue_off
  return 0
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
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
echo "$out"
# Non-cluster names are forwarded upstream by k3rs-dns (CoreDNS `forward .
# /etc/resolv.conf`, crates/dns/src/forward.rs, #4482): a ClusterFirst pod
# lists only 10.96.0.10, so an external name must resolve through it too.
ext="${EXTERNAL_NAME:-dns.google}"
out="$(k -n $NS exec acc-bb-node2 -- nslookup "$ext" 10.96.0.10 2>&1)" || true
grep -A3 "^Name:" <<<"$out" | grep -Eq "^Address:?[[:space:]]+[0-9a-fA-F.:]+" \
  || fail 5 "nslookup $ext via 10.96.0.10 (upstream forwarding) returned no address" "$out"
pass 5 "nslookup -> $kip; $ext forwarded upstream"; echo "$out"

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
# Journal start for check 14's positive control (each node's own clock).
sec_since_cp="$(nssh "$CP" 'date +%s')"
sec_since_n3="$(nssh node3 'date +%s')"
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

# 15. api-server -> kubelet serving-cert verification
CP_IP="$(node_ip "$CP")"
N3_IP="$(node_ip node3)"
# Each agent's serving cert names the InternalIP its kubelet registered (the
# IP the api-server dials), so the verified dial succeeds on every agent.
for n in node2 node3; do
  nip="$(k get node "$n" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}' 2>&1)" || true
  out="$(nssh "$CP" "sudo openssl s_client -connect $nip:10250 -CAfile /var/lib/k3rs/tls/server-ca.crt -verify_ip $nip -verify_return_error </dev/null 2>&1 | grep 'Verify return code'" || true)"
  grep -q 'Verify return code: 0 (ok)' <<<"$out" \
    && pass 15 "kubelet_serving_cert_verified $n:10250 cert chains to the server CA for its InternalIP $nip" \
    || sfail 15 "kubelet_serving_cert_verified $n:10250 (InternalIP '$nip') against server-ca.crt" "$out"
done
# Rogue kubelet on node3: self-signed cert with node3's SANs on :10251, and
# node1's connections to :10250 redirected to it for the duration. The
# REDIRECT rule also expires on node3 by itself after 90s, so even a killed
# run (or a lost ssh) cannot leave node1 cut off from node3's kubelet.
ROGUE_RULE="PREROUTING -p tcp -s $CP_IP --dport 10250 -j REDIRECT --to-ports 10251"
rogue_off() {
  nssh node3 "sudo sh -c 'while iptables -t nat -D $ROGUE_RULE 2>/dev/null; do :; done; rm -f /tmp/rogue.key /tmp/rogue.crt; pkill -f \"[o]penssl s_server -accept 10251\" 2>/dev/null; pkill -f \"[k]3rs-rogue-expire\" 2>/dev/null; true'" >/dev/null 2>&1 || true
}
ROGUE_STARTED=1
nssh node3 "sudo sh -s" <<ROGUE >/dev/null 2>&1 || sfail 15 "could not start the rogue kubelet on node3"
set -e
cd /tmp
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout rogue.key -out rogue.crt -days 1 -subj /CN=system:node:node3 -addext "subjectAltName=IP:$N3_IP,DNS:node3" >/dev/null 2>&1
nohup timeout 120 openssl s_server -accept 10251 -cert rogue.crt -key rogue.key -www -quiet >/dev/null 2>&1 &
sleep 1
setsid sh -c 'sleep 90; iptables -t nat -D $ROGUE_RULE; rm -f /tmp/rogue.key /tmp/rogue.crt' k3rs-rogue-expire </dev/null >/dev/null 2>&1 &
iptables -t nat -I $ROGUE_RULE
ROGUE
out="$(k -n $NS logs acc-nginx-node3 --tail=5 2>&1)" && rc=0 || rc=$?
if [ "$rc" -ne 0 ] && ! grep -q 'GET / HTTP' <<<"$out"; then
  pass 15 "kubelet_serving_cert_verified rogue kubelet cert refused: $(tail -1 <<<"$out" | cut -c1-160)"
else
  sfail 15 "kubelet_serving_cert_verified rogue kubelet was NOT refused (rc=$rc)" "$out"
fi
out="$(k -n $NS logs acc-nginx-node3 --tail=5 --insecure-skip-tls-verify-backend 2>&1)" || true
grep -q 's_server' <<<"$out" \
  && pass 15 "kubelet_serving_cert_verified --insecure-skip-tls-verify-backend reaches the rogue (InsecureSkipTLSVerifyTransport)" \
  || sfail 15 "kubelet_serving_cert_verified --insecure-skip-tls-verify-backend did not reach the rogue" "$out"
rogue_off
ROGUE_STARTED=0
if nssh node3 "sudo iptables -t nat -C $ROGUE_RULE" >/dev/null 2>&1; then
  sfail 15 "kubelet_serving_cert_verified rogue REDIRECT rule still on node3 after cleanup: $ROGUE_RULE"
else
  pass 15 "kubelet_serving_cert_verified rogue REDIRECT rule removed from node3"
fi
out="$(k -n $NS logs acc-nginx-node3 --tail=50 2>&1)" || true
grep -q 'GET / HTTP' <<<"$out" && pass 15 "kubelet_serving_cert_verified logs work again with the real kubelet" \
  || sfail 15 "kubelet_serving_cert_verified logs after removing the rogue" "$out"

# 16. k3rs-managed RBAC is reconciled on start (autoupdate + current rules)
for r in system:k3rs-dns system:k3rs-event-gc; do
  au="$(k get clusterrole "$r" -o jsonpath='{.metadata.annotations.rbac\.authorization\.kubernetes\.io/autoupdate}' 2>&1)" || true
  expect 16 true "$au" "k3rs_rbac_reconciled clusterrole $r autoupdate"
  au="$(k get clusterrolebinding "$r" -o jsonpath='{.metadata.annotations.rbac\.authorization\.kubernetes\.io/autoupdate}' 2>&1)" || true
  expect 16 true "$au" "k3rs_rbac_reconciled clusterrolebinding $r autoupdate"
done
can="$(k auth can-i watch endpointslices.discovery.k8s.io --as system:k3rs-dns 2>&1)" || true
expect 16 yes "$can" "k3rs_rbac_reconciled system:k3rs-dns can watch endpointslices"

# 17. a legacy service-account token Secret authenticates
k -n $NS delete secret acc-legacy-token --ignore-not-found >/dev/null 2>&1 || true
k -n $NS delete sa acc-legacy --ignore-not-found >/dev/null 2>&1 || true
k -n $NS create sa acc-legacy >/dev/null
k -n $NS apply -f - >/dev/null <<'SECRET'
apiVersion: v1
kind: Secret
metadata:
  name: acc-legacy-token
  annotations:
    kubernetes.io/service-account.name: acc-legacy
type: kubernetes.io/service-account-token
SECRET
tok=""
for _ in $(seq 1 30); do
  tok="$(k -n $NS get secret acc-legacy-token -o jsonpath='{.data.token}' 2>/dev/null | base64 -d 2>/dev/null || true)"
  [ -n "$tok" ] && break
  sleep 1
done
if [ -z "$tok" ]; then
  sfail 17 "legacy_sa_token_authenticates: acc-legacy-token got no token in 30s"
else
  hdr="$(cut -d. -f1 <<<"$tok" | tr '_-' '/+' | base64 -d 2>/dev/null || true)"
  out="$(nssh node2 "curl -sk -m 10 -X POST -H 'Authorization: Bearer $tok' -H 'Content-Type: application/json' -d '{\"apiVersion\":\"authentication.k8s.io/v1\",\"kind\":\"SelfSubjectReview\"}' https://$CP:6443/apis/authentication.k8s.io/v1/selfsubjectreviews" 2>&1)" || true
  grep -q '"username": *"system:serviceaccount:default:acc-legacy"' <<<"$out" \
    && pass 17 "legacy_sa_token_authenticates as system:serviceaccount:default:acc-legacy (header $hdr)" \
    || sfail 17 "legacy_sa_token_authenticates SelfSubjectReview with the Secret's token (header $hdr)" "$out"
fi

# 18. 401s are negotiated Status objects (bad bearer token)
out="$(nssh node2 "curl -sk -m 10 -i -H 'Authorization: Bearer not-a-token' https://$CP:6443/api" 2>&1)" || true
if grep -q '^HTTP/[0-9.]* 401' <<<"$out" && grep -qi '^content-type: application/json' <<<"$out" \
   && grep -q '"kind": *"Status"' <<<"$out" && grep -q '"reason": *"Unauthorized"' <<<"$out"; then
  pass 18 "unauthorized_is_status bad bearer -> 401 Status (reason Unauthorized)"
else
  sfail 18 "unauthorized_is_status bad bearer token" "$out"
fi

# 14. no 403 flood from the embedded identities in steady state
STEADY_WINDOW="${STEADY_WINDOW:-60}"
# Deferred (documented in README): the Service and APIServiceAvailability
# controllers have no upstream role (upstream does that work inside
# kube-apiserver) and their periodic live GETs (no query string, empty RBAC
# reason) as system:kube-controller-manager are denied; ClusterIP/NodePort
# allocation and APIService availability are done by the api-server itself, so
# nothing breaks. Pass FORBIDDEN_ALLOW='^$' to count them as failures.
FORBIDDEN_ALLOW="${FORBIDDEN_ALLOW:-Forbidden uri=/api/v1/namespaces/(default/services/kubernetes|kube-system/services/kube-dns) reason=$|Forbidden uri=/apis/apiregistration\.k8s\.io/v1/apiservices/v[0-9a-z]+\.[a-z0-9.]* reason=$}"
# journal <node> <since-epoch>: the k3rs journal, ANSI-stripped; fails (and
# prints nothing) when ssh/journalctl fails.
journal() {
  local out
  out="$(nssh "$1" "sudo journalctl -u k3rs --no-pager -o cat --since @$2")" || return 1
  sed -E 's/\x1b\[[0-9;]*m//g' <<<"$out"
}
# Positive control: the deliberate denials of checks 9, 10 (api-server debug
# log on node1) and 12 (kubelet debug log on node3) must be in the journals,
# or a 0 below would only mean the denials are not logged.
cp_log="$(journal "$CP" "$sec_since_cp")" || cp_log=""
n3_log="$(journal node3 "$sec_since_n3")" || n3_log=""
for want in 'Forbidden uri=/api/v1/namespaces/kube-system/secrets reason=' \
            'Forbidden uri=/api/v1/namespaces/kube-system/secrets/node3.node-password.k3rs reason='; do
  grep -qF "$want" <<<"$cp_log" && pass 14 "positive control on $CP: '$want'" \
    || sfail 14 "positive control: '$want' not in $CP's journal (is the server's RUST_LOG from sync.sh set?)"
done
grep -qF 'Forbidden user=system:node:node2' <<<"$n3_log" \
  && pass 14 "positive control on node3: kubelet denial of system:node:node2 logged" \
  || sfail 14 "positive control: node3's kubelet denial of system:node:node2 not in its journal (RUST_LOG from sync.sh?)"

since="$(nssh "$CP" 'date +%s')"
echo "idling ${STEADY_WINDOW}s for the steady-state log scan (since @$since)"
sleep "$STEADY_WINDOW"
total=0
for n in "${NODES[@]}"; do
  if ! log="$(journal "$n" "$since")" || [ -z "$log" ]; then
    sfail 14 "no_forbidden_flood: could not read $n's journal (or it is empty) for the window"
    continue
  fi
  lines="$(grep -Ei '(\b403\b|forbidden)' <<<"$log" || true)"
  all=$(grep -c . <<<"$lines" || true)
  if [ -n "$FORBIDDEN_ALLOW" ]; then
    left="$(grep -Ev "$FORBIDDEN_ALLOW" <<<"$lines" || true)"
  else
    left="$lines"
  fi
  bad=$(grep -c . <<<"$left" || true)
  echo "$n: $all 403/Forbidden lines in ${STEADY_WINDOW}s ($bad not in FORBIDDEN_ALLOW; $(grep -c . <<<"$log") journal lines read)"
  # distinct messages, thread ids/uids stripped
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
echo "ALL 18 CHECKS PASSED"
