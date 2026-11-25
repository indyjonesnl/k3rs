# shellcheck shell=bash
# Shared by up.sh / sync.sh.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/kubernetes-rs-target}"
BIN_DIR="${BIN_DIR:-$CARGO_TARGET_DIR/release-fast}"
PROJECT=kubernetes-rs
# The packaged 0.1.0 in ~/.cargo/bin is stale (no `config`/`ports:`). Use the release
# build of microcompose main; override with MICROCOMPOSE=.
MC="${MICROCOMPOSE:-}"
[ -n "$MC" ] || { [ -x "$CARGO_TARGET_DIR/release/microcompose" ] && MC="$CARGO_TARGET_DIR/release/microcompose" || MC=microcompose; }
KEY="$HOME/.local/share/microcompose/$PROJECT/ssh/id_ed25519"
NODES=(node1 node2 node3)
CP=node1
SSH_OPTS=(-i "$KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5)

node_ip() { "$MC" -f "$HERE/compose.yaml" ps --json | python3 -c "import json,sys;print(next(s['address'] for s in json.load(sys.stdin) if s['service']=='$1'))"; }
nssh()    { local n=$1; shift; ssh "${SSH_OPTS[@]}" "microcompose@$(node_ip "$n")" "$@"; }
nscp()    { local n=$1; shift; scp "${SSH_OPTS[@]}" "$@" "microcompose@$(node_ip "$n"):/tmp/"; }
