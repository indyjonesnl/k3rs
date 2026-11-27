#!/usr/bin/env bash
# Workflow-side wrapper around select-affected.sh: decides full vs scoped for
# the current GitHub event and writes mode/packages/sqlite/reason to
# the file given as $1 (default stdout). Rules: docs/CI.md.
#
#   not a pull_request            -> full   (push to main, schedule, dispatch)
#   PR carries label `ci:full`    -> full   (read live from the API, so a
#                                            workflow re-run sees a label added
#                                            after the event fired)
#   label lookup fails            -> full   (fail safe)
#   otherwise                     -> select-affected.sh on the merge-base diff
#
# Env: EVENT_NAME, BASE_SHA, PR_NUMBER, GH_TOKEN, GITHUB_REPOSITORY.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
out=${1:-/dev/stdout}   # KEY=VALUE file (the workflow passes a temp file)

full() {
  printf 'mode=full\npackages=\nreason=%s\nsqlite=true\n' "$1" | tee -a "$out" >/dev/null
  echo "::notice::CI scope: full workspace ($1)"
  exit 0
}

[ "${EVENT_NAME:-}" = pull_request ] || full "event ${EVENT_NAME:-unknown} always runs the full workspace"

labels=$(curl -fsS --retry 3 \
  -H "Authorization: Bearer ${GH_TOKEN:-}" -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/labels?per_page=100" \
  | jq -r '.[].name') || full "could not read PR labels (fail-safe)"
if printf '%s\n' "$labels" | grep -qx 'ci:full'; then full "PR has the ci:full label"; fi

result=$(git diff --name-only "${BASE_SHA}...HEAD" | "$here/select-affected.sh" --files -)
printf '%s\n' "$result" | tee -a "$out" >/dev/null
echo "::notice::CI scope: $(printf '%s\n' "$result" | sed -n 's/^mode=//p') ($(printf '%s\n' "$result" | sed -n 's/^reason=//p'))"
