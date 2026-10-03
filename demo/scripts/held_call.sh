#!/usr/bin/env bash
# Run a demo agent task whose payment the gateway holds for approval, decide the
# held call as a human would, and check how the agent ends.
#
#   demo/scripts/held_call.sh <task> <approve|deny> <expected exit status> [--restart]
#
# With --restart the gateway container is restarted while the call waits: the
# call lives in Postgres, the agent reconnects on its own, and the decision is
# made on the new gateway. Exit 0 means the agent ended as expected.
set -euo pipefail

task=$1 decision=$2 expected=$3 restart=${4:-}
compose=(docker compose -f "$(dirname "$0")/../compose.yaml")
log=$(mktemp)

"${compose[@]}" run --rm -T -e AGENT_TASK="$task" agent >"$log" 2>&1 &
agent=$!

held=""
for _ in $(seq 120); do
  held=$("${compose[@]}" run --rm -T approver approvals list --json 2>/dev/null |
    python3 -c 'import json, sys; calls = json.load(sys.stdin); print(calls[0]["id"] if calls else "")') || true
  [ -n "$held" ] && break
  if ! kill -0 "$agent" 2>/dev/null; then
    echo "the agent finished without being held:"
    cat "$log"
    exit 1
  fi
  sleep 1
done
if [ -z "$held" ]; then
  echo "no call was held"
  cat "$log"
  exit 1
fi
echo "held call: $held"

if [ "$restart" = "--restart" ]; then
  "${compose[@]}" restart gateway
  echo "gateway restarted while the call waited"
fi

"${compose[@]}" run --rm -T approver approvals "$decision" "$held" --reason "decided by held_call.sh"

set +e
wait "$agent"
status=$?
set -e
cat "$log"
if [ "$status" -ne "$expected" ]; then
  echo "expected the agent to exit $expected, got $status"
  exit 1
fi
