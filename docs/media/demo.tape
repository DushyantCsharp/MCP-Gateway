# Renders docs/media/demo.gif with vhs (https://github.com/charmbracelet/vhs): a payment the policy
# holds for a human survives a gateway restart, and is made once after approval.
#
#   docker compose -f demo/compose.yaml up --build --wait
#   docker compose -f demo/compose.yaml run --rm agent    # once, so the tokens exist
#   vhs docs/media/demo.tape
#
# Every command runs live against the demo stack, at real speed. Two steps are hidden: the
# shell set-up, and looking up the held call's id for the approve command (about 4 seconds).

Output docs/media/demo.gif
Require docker

Set Shell bash
Set FontSize 15
Set Width 1280
Set Height 760
Set Padding 20
Set TypingSpeed 22ms
Set Theme "Catppuccin Mocha"

Hide
Type `export COMPOSE_PROGRESS=quiet PS1='\[\e[1;32m\]$\[\e[0m\] ' && alias c='docker compose -f demo/compose.yaml'`
Enter
Type `held() { docker compose -f demo/compose.yaml run --rm --no-deps -T approver approvals list --json | python3 -c 'import json, sys; print(json.load(sys.stdin)[0]["id"])'; } && clear`
Enter
Show

Type "# An agent pays an invoice of 18,450. The policy says a human approves anything over 10,000."
Enter
Type "c run --rm --no-deps -T -e PYTHONUNBUFFERED=1 -e AGENT_TASK=pay-invoice agent </dev/null &"
Enter
Wait+Screen@60s /held call/
Sleep 3s

Enter
Type "# The call waits in Postgres. Restart the gateway while it waits:"
Enter
Type "c restart gateway && c ps gateway --format '{{.Service}}: {{.Status}}'"
Enter
Wait+Line@30s /\$\s*$/
Sleep 3s

Type "# A person approves it, through the new gateway process:"
Enter
Type "c run --rm --no-deps -T approver approvals list"
Enter
Wait+Screen@30s /pending/
Sleep 2s
Hide
# Fetch the held call's id, then erase this line from the screen.
Type `id=$(held); printf '\e[1A\e[2K'`
Enter
Wait+Line@30s /\$\s*$/
Show
Type "c run --rm --no-deps -T approver approvals approve $id --reason 'matches PO 4471'"
Enter
Wait+Screen@60s /TASK COMPLETE/
Sleep 3s

Enter
Type "# Paid once, after the restart. Every call, hold and decision is in the hash-chained audit log:"
Enter
Type "c exec gateway customs verify-audit --key-env CUSTOMS_AUDIT_KEY"
Enter
Wait+Screen@30s / ok/
Sleep 6s
