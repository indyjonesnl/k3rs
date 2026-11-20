#!/usr/bin/env bash
# Push the one `k3rs` binary into the running VMs and (re)start k3rs.service.
# Idempotent; this is the inner dev loop:
#   make build-fast ARGS="-p k3rs --bin k3rs" && ./sync.sh
#
# node1 runs `k3rs server`; once it has written its join token
# (/var/lib/k3rs/token), the token is copied (0600) to /etc/k3rs/token on
# node2/node3, which then run `k3rs agent --server https://node1:6443`.
# No certs are copied: the server mints its PKI, agents fetch theirs by token.
# usage: ./sync.sh [path/to/k3rs]   (default: $BIN_DIR/k3rs)
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

BIN="${1:-$BIN_DIR/k3rs}"
[ -x "$BIN" ] || { echo "k3rs binary not found: $BIN (make build-fast ARGS=\"-p k3rs --bin k3rs\")" >&2; exit 1; }
TOKEN_FILE=/var/lib/k3rs/token
TOKEN_WAIT="${TOKEN_WAIT:-120}"
# The server logs each denied request (`Forbidden uri=...`) at debug;
# acceptance.sh check 14 counts them. EnvironmentFile overrides the unit's
# Environment=RUST_LOG.
# Every kubelet logs its own denials at debug (`Forbidden user=...`,
# server_auth.rs, upstream pkg/kubelet/server/auth.go); check 14's positive
# control looks for them.
SERVER_RUST_LOG="${SERVER_RUST_LOG:-info,k3rs_api_server::authorization_filter=debug,k3rs_kubelet::server_auth=debug}"
AGENT_RUST_LOG="${AGENT_RUST_LOG:-info,k3rs_kubelet::server_auth=debug}"

# push <node> <role> <role-args>: install binary + node.env, restart k3rs.
push() {
  local n=$1 role=$2 args=$3 ip
  ip="$(node_ip "$n")"
  until nssh "$n" true 2>/dev/null; do echo "waiting for ssh on $n"; sleep 3; done
  nssh "$n" 'cloud-init status --wait >/dev/null 2>&1 || true'
  nscp "$n" "$BIN" >/dev/null
  nssh "$n" "sudo sh -s" <<REMOTE
set -e
mkdir -p /etc/k3rs
install -m755 /tmp/$(basename "$BIN") /usr/local/bin/k3rs.new && rm -f /tmp/$(basename "$BIN")
mv -f /usr/local/bin/k3rs.new /usr/local/bin/k3rs
cat > /etc/k3rs/node.env <<ENV
K3RS_ROLE=$role
NODE_IP=$ip
K3RS_ARGS=$args
RUST_LOG=$( [ "$role" = server ] && echo "$SERVER_RUST_LOG" || echo "$AGENT_RUST_LOG" )
ENV
systemctl daemon-reload
systemctl enable k3rs >/dev/null 2>&1
systemctl restart k3rs
REMOTE
  echo "$n: k3rs $role restarted (node-ip $ip)"
}

# Server first. The serving cert gets node1 (+ node name/IPs, localhost,
# 127.0.0.1) as SANs, so agents can pin https://node1:6443 and the host can
# use the forwarded https://127.0.0.1:6443.
push "$CP" server "--tls-san $CP"

echo "waiting up to ${TOKEN_WAIT}s for $CP:$TOKEN_FILE"
token=""
for _ in $(seq 1 "$TOKEN_WAIT"); do
  token="$(nssh "$CP" "sudo cat $TOKEN_FILE 2>/dev/null" || true)"
  [ -n "$token" ] && break
  sleep 1
done
[ -n "$token" ] || { echo "no join token at $CP:$TOKEN_FILE after ${TOKEN_WAIT}s; journal:" >&2; nssh "$CP" 'sudo journalctl -u k3rs --no-pager -n 50' >&2 || true; exit 1; }

for n in "${NODES[@]}"; do
  [ "$n" = "$CP" ] && continue
  until nssh "$n" true 2>/dev/null; do echo "waiting for ssh on $n"; sleep 3; done
  printf '%s\n' "$token" | nssh "$n" 'sudo sh -c "umask 077; mkdir -p /etc/k3rs; cat > /etc/k3rs/token; chmod 600 /etc/k3rs/token"'
  push "$n" agent "--server https://$CP:6443 --token-file /etc/k3rs/token"
done
