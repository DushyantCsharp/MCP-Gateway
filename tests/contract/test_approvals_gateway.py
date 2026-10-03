"""Weekend 6: calls that wait for a human, end to end through a running gateway.

The example finance policy sends payments over 10,000 for approval. Agents use
the official SDK client, unmodified: a held call simply takes as long as the
human does. A payment counts as made only if the finance server recorded it.
"""

import json
import re
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import anyio
import httpx2
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp_types import LoggingMessageNotificationParams
from mcp_types.version import LATEST_MODERN_VERSION

from customs_demo import finance_server, workspace_server
from customs_demo._serve import http_app
from customs_demo.agent import TaskBlockedError, run_task
from mcp_customs import jsonrpc
from mcp_customs.approvals import TOKEN_PREFIX, MemoryApprovalStore
from mcp_customs.audit import MemoryAuditStore
from mcp_customs.pipeline.policy import PolicyStage
from mcp_customs.policy import RulePolicy
from mcp_customs.proxy.sse import SseParser
from tests.contract.conftest import Gateway, make_config, running_gateway
from tests.support.clients import ACCEPT, TEST_AUDIENCE, TEST_SECRET, RawSession, answer_of, mint
from tests.support.finance_cases import transfer
from tests.support.recorder import Recorder
from tests.support.servers import serve_in_thread

pytestmark = [pytest.mark.anyio, pytest.mark.contract]

POLICY = Path(__file__).parents[2] / "policies" / "examples" / "finance-agent.yaml"
APPROVER = mint("alice", roles=("approver",), ttl=3600)
AP = mint("ap-agent", ttl=3600)
AUTH = {"jwt": {"audience": TEST_AUDIENCE, "secret": TEST_SECRET}}
FAST = {"dsn": "postgresql://unused", "stream_s": 1, "retry_ms": 300, "poll_s": 0.1}


@dataclass(frozen=True)
class Approving:
    gateway: Gateway
    finance: Recorder
    finance_base: str
    audit: MemoryAuditStore


@pytest.fixture(scope="module")
def approving() -> Iterator[Approving]:
    workspace = Recorder(http_app(workspace_server.build_server(), json_response=False))
    finance = Recorder(http_app(finance_server.build_server(), json_response=True))
    with serve_in_thread(workspace) as ws, serve_in_thread(finance) as fin:
        config = make_config(
            {"workspace": f"{ws}/mcp", "finance": f"{fin}/mcp"},
            auth=AUTH,
            stages=[{"type": "policy", "file": str(POLICY)}],
            approvals=FAST,
            audit={"dsn": "postgresql://unused", "chain": "approvals"},
        )
        audit = MemoryAuditStore()
        with running_gateway(config, approval_store=MemoryApprovalStore(), audit_store=audit) as gateway:
            yield Approving(gateway, finance, fin, audit)


async def api(
    gateway: Gateway, method: str, path: str, *, token: str | None = APPROVER, **kwargs: Any
) -> Any:
    headers = {"authorization": f"Bearer {token}"} if token else {}
    async with httpx2.AsyncClient() as http:
        return await http.request(method, f"{gateway.base}{path}", headers=headers, **kwargs)


async def decide(gateway: Gateway, held_id: str, decision: str, reason: str | None = None) -> Any:
    body = {"decision": decision, "reason": reason}
    return await api(gateway, "POST", f"/approvals/api/calls/{held_id}/decision", json=body)


async def pending_call(gateway: Gateway, memo: str) -> dict[str, Any]:
    """The pending held call for the payment with this memo, once it appears."""
    with anyio.fail_after(10):
        while True:
            for call in (await api(gateway, "GET", "/approvals/api/calls")).json():
                if (call.get("arguments") or {}).get("memo") == memo:
                    return dict(call)
            await anyio.sleep(0.05)


async def payments(approving: Approving, memo: str) -> list[dict[str, Any]]:
    async with httpx2.AsyncClient() as http:
        made = (await http.get(f"{approving.finance_base}/transfers")).json()
    return [payment for payment in made if payment["memo"] == memo]


def memo() -> str:
    return f"INV-{uuid.uuid4().hex[:10]}"


def events(response: httpx2.Response) -> list[Any]:
    return list(SseParser().feed(response.content))


def modern_headers(token: str, **extra: str) -> dict[str, str]:
    return {
        "accept": ACCEPT,
        "authorization": f"Bearer {token}",
        "mcp-protocol-version": LATEST_MODERN_VERSION,
        **extra,
    }


# -- the agent's view ------------------------------------------------------------------------------


@pytest.mark.parametrize("decision", ["approve", "deny"])
async def test_a_large_payment_waits_for_a_human(mode: str, approving: Approving, decision: str) -> None:
    reference = memo()
    notices: list[Any] = []

    async def on_log(params: LoggingMessageNotificationParams) -> None:
        notices.append(params.data)

    results: list[Any] = []
    headers = {"authorization": f"Bearer {AP}"}
    async with (
        httpx2.AsyncClient(headers=headers, timeout=httpx2.Timeout(30.0, read=300.0)) as http,
        Client(
            streamable_http_client(approving.gateway.url("finance"), http_client=http),
            mode=mode,
            logging_callback=on_log,
        ) as client,
    ):
        await client.list_tools()

        async def pay() -> None:
            results.append(
                await client.call_tool("transfer_funds", transfer(amount="18450.00", memo=reference))
            )

        async with anyio.create_task_group() as tasks:
            tasks.start_soon(pay)
            call = await pending_call(approving.gateway, reference)
            await anyio.sleep(0.5)  # the agent is still waiting, and nothing has been paid
            assert results == []
            assert await payments(approving, reference) == []
            decided = await decide(approving.gateway, call["id"], decision, "checked against the PO")
            assert decided.status_code == 200, decided.text

    (result,) = results
    made = await payments(approving, reference)
    if decision == "approve":
        assert not result.is_error
        assert result.structured_content is not None
        assert len(made) == 1
        final = (await api(approving.gateway, "GET", f"/approvals/api/calls/{call['id']}")).json()
        assert (final["status"], final["decided_by"]) == ("completed", "alice")
    else:
        assert result.is_error
        assert (
            result.content[0].model_dump()["text"] == "Denied at approval by alice: checked against the PO."
        )
        assert made == []
    assert call["reason"] == "needs approval under rule 'ap-large-payments-need-approval'"
    assert notices
    assert "waiting for a human's approval" in notices[0]["message"]


async def test_the_scripted_agent_pays_once_approved(mode: str, approving: Approving) -> None:
    token = mint("ap-agent")
    reports: list[Any] = []
    gateway = approving.gateway

    async def pay() -> None:
        reports.append(
            await run_task(
                gateway.url("workspace"), gateway.url("finance"), mode=mode, token=token, task="pay-invoice"
            )
        )

    async with anyio.create_task_group() as tasks:
        tasks.start_soon(pay)
        call = await pending_call(gateway, "inv-2026-091")
        await decide(gateway, call["id"], "approve")
    assert reports[0].transfer_id is not None


async def test_the_scripted_agent_reports_a_denied_payment(mode: str, approving: Approving) -> None:
    gateway = approving.gateway

    async def pay() -> None:
        with pytest.raises(TaskBlockedError, match="Denied at approval by alice"):
            await run_task(
                gateway.url("workspace"),
                gateway.url("finance"),
                mode=mode,
                token=mint("ap-agent"),
                task="pay-invoice",
            )

    async with anyio.create_task_group() as tasks:
        tasks.start_soon(pay)
        call = await pending_call(gateway, "inv-2026-091")
        await decide(gateway, call["id"], "deny")


# -- resuming --------------------------------------------------------------------------------------


async def test_an_approved_call_is_made_when_the_client_reconnects(approving: Approving) -> None:
    """The client was away when the decision came; its reconnect makes the call, once."""
    reference = memo()
    url = approving.gateway.url("finance")
    async with httpx2.AsyncClient(timeout=30) as http:
        session = RawSession(http, url, AP, modern=True)
        request_id, held = await session.request(
            "tools/call", {"name": "transfer_funds", "arguments": transfer(amount="18450.00", memo=reference)}
        )
        token = events(held)[0].id
        assert token is not None
        assert token.startswith(TOKEN_PREFIX)
        assert answer_of(held) is None  # the stream ended without an answer
        call = await pending_call(approving.gateway, reference)
        await decide(approving.gateway, call["id"], "approve")
        assert await payments(approving, reference) == []  # approval alone makes nothing

        resumed = await http.get(url, headers=modern_headers(AP, **{"last-event-id": token}))
        again = await http.get(url, headers=modern_headers(AP, **{"last-event-id": token}))

    answer = answer_of(resumed)
    assert answer["id"] == request_id
    assert answer["result"]["isError"] is False
    assert answer_of(again) == answer  # the stored answer, not a second payment
    assert len(await payments(approving, reference)) == 1
    assert [body.get("id") for _, body in approving.finance.received if isinstance(body, dict)].count(
        request_id
    ) == 1


async def test_a_resume_token_works_only_for_the_agent_that_holds_it(approving: Approving) -> None:
    reference = memo()
    url = approving.gateway.url("finance")
    async with httpx2.AsyncClient(timeout=30) as http:
        session = RawSession(http, url, AP, modern=True)
        _, held = await session.request(
            "tools/call", {"name": "transfer_funds", "arguments": transfer(amount="18450.00", memo=reference)}
        )
        token = events(held)[0].id or ""
        other = await http.get(url, headers=modern_headers(mint("someone-else"), **{"last-event-id": token}))
        guessed = await http.get(url, headers=modern_headers(AP, **{"last-event-id": TOKEN_PREFIX + "guess"}))
        wrong_upstream = await http.get(
            approving.gateway.url("workspace"), headers=modern_headers(AP, **{"last-event-id": token})
        )
        mine = await http.get(url, headers=modern_headers(AP, **{"last-event-id": token}))
    assert (other.status_code, guessed.status_code, wrong_upstream.status_code) == (404, 404, 404)
    assert mine.status_code == 200
    assert events(mine)[0].id == token  # still waiting: the stream opens with the same token
    call = await pending_call(approving.gateway, reference)
    await decide(approving.gateway, call["id"], "deny")


async def test_a_client_that_cannot_wait_is_told_why(approving: Approving) -> None:
    body = {
        "jsonrpc": "2.0",
        "id": "no-sse",
        "method": "tools/call",
        "params": {
            "name": "transfer_funds",
            "arguments": transfer(amount="18450.00", memo=memo()),
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": LATEST_MODERN_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        },
    }
    headers = {
        **modern_headers(AP),
        "accept": "application/json",
        "mcp-method": "tools/call",
        "mcp-name": "transfer_funds",
    }
    async with httpx2.AsyncClient() as http:
        response = await http.post(approving.gateway.url("finance"), json=body, headers=headers)
    result = response.json()["result"]
    assert result["isError"] is True
    assert "it does not accept text/event-stream" in result["content"][0]["text"]
    assert not approving.finance.saw("no-sse")


# -- the record ------------------------------------------------------------------------------------


async def test_holds_decisions_and_the_approved_call_are_all_audited(approving: Approving) -> None:
    reference = memo()
    url = approving.gateway.url("finance")
    async with httpx2.AsyncClient(timeout=30) as http:
        session = RawSession(http, url, AP, modern=True)
        _, held = await session.request(
            "tools/call", {"name": "transfer_funds", "arguments": transfer(amount="18450.00", memo=reference)}
        )
        call = await pending_call(approving.gateway, reference)
        await decide(approving.gateway, call["id"], "approve", "PO 4471")
        await http.get(url, headers=modern_headers(AP, **{"last-event-id": events(held)[0].id or ""}))

    def result_for(rows: list[dict[str, Any]], request: dict[str, Any]) -> dict[str, Any] | None:
        return next((r for r in rows if r["type"] == "result" and r.get("request") == request["id"]), None)

    with anyio.fail_after(5):
        while True:
            rows = [json.loads(row.body) for row in approving.audit.rows]
            requests = [
                r for r in rows if r["type"] == "request" and call["id"] in json.dumps(r.get("stages"))
            ]
            if len(requests) == 2 and result_for(rows, requests[1]) is not None:
                break
            await anyio.sleep(0.05)
    assert [row["decision"] for row in requests] == ["held", "forwarded"]
    assert requests[0]["stages"]["approval"] == {"held": call["id"], "status": "pending"}
    assert requests[1]["stages"]["approval"]["approved_by"] == "alice"
    assert requests[1]["stages"]["policy"]["approved_by"] == "alice"
    decision = next(r for r in rows if r["type"] == "approval" and r["held"] == call["id"])
    assert (decision["decision"], decision["approver"], decision["reason"]) == (
        "approved",
        "alice",
        "PO 4471",
    )
    assert result_for(rows, requests[1])["outcome"] == "ok"  # type: ignore[index]


# -- who may decide --------------------------------------------------------------------------------


async def test_only_approvers_may_decide_and_never_their_own_calls(approving: Approving) -> None:
    gateway = approving.gateway
    reference = memo()
    async with httpx2.AsyncClient(timeout=30) as http:
        await RawSession(http, gateway.url("finance"), AP, modern=True).request(
            "tools/call", {"name": "transfer_funds", "arguments": transfer(amount="18450.00", memo=reference)}
        )
    call = await pending_call(gateway, reference)
    path = f"/approvals/api/calls/{call['id']}/decision"
    approve = {"decision": "approve"}

    assert (await api(gateway, "GET", "/approvals/api/calls", token=None)).status_code == 401
    assert (await api(gateway, "POST", path, token=AP, json=approve)).status_code == 403
    self_approver = mint("ap-agent", roles=("approver",))
    refused = await api(gateway, "POST", path, token=self_approver, json=approve)
    assert (refused.status_code, refused.json()) == (403, {"error": "an agent cannot approve its own call"})
    assert (await api(gateway, "POST", path, json={"decision": "maybe"})).status_code == 400
    assert (await api(gateway, "POST", path, content=b"[1]")).status_code == 400
    assert (await api(gateway, "POST", "/approvals/api/calls/nope/decision", json=approve)).status_code == 404

    assert (await decide(gateway, call["id"], "deny")).status_code == 200
    again = await decide(gateway, call["id"], "approve")
    assert (again.status_code, again.json()) == (409, {"error": "the call is already denied"})


async def test_the_approvals_page(approving: Approving) -> None:
    gateway = approving.gateway
    reference = memo()
    arguments = transfer(amount="18450.00", memo=reference + " <script>alert(1)</script>")
    async with httpx2.AsyncClient(timeout=30) as http:
        await RawSession(http, gateway.url("finance"), AP, modern=True).request(
            "tools/call", {"name": "transfer_funds", "arguments": arguments}
        )
    with anyio.fail_after(10):
        while True:
            calls = (await api(gateway, "GET", "/approvals/api/calls")).json()
            call = next((c for c in calls if c["arguments"]["memo"].startswith(reference)), None)
            if call:
                break
            await anyio.sleep(0.05)

    async with httpx2.AsyncClient(base_url=gateway.base, follow_redirects=False) as browser:
        signin = await browser.get("/approvals")
        assert signin.status_code == 200
        assert "Paste an approver token" in signin.text
        assert "script-src" not in signin.headers["content-security-policy"]  # no scripts at all
        assert (await browser.post("/approvals/login", data={"token": AP})).status_code == 403

        login = await browser.post("/approvals/login", data={"token": APPROVER})
        assert login.status_code == 303
        cookie = login.headers["set-cookie"].lower()
        assert all(flag in cookie for flag in ("httponly", "samesite=strict", "path=/approvals", "secure"))

        # The demo-style gateway runs on plain HTTP; send the Secure cookie by hand.
        browser.cookies.set("customs_approver", APPROVER)
        page = await browser.get("/approvals")
        assert page.status_code == 200
        assert "Signed in as alice" in page.text
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page.text
        assert "<script>" not in page.text
        csrf = re.search(
            rf"action='/approvals/{call['id']}/decision'><input type=hidden name=csrf value='(\w+)'",
            page.text,
        )
        assert csrf is not None

        path = f"/approvals/{call['id']}/decision"
        forged = await browser.post(path, data={"decision": "approve", "csrf": "0" * 64})
        assert forged.status_code == 403
        done = await browser.post(
            path, data={"decision": "deny", "reason": "duplicate", "csrf": csrf.group(1)}
        )
        assert done.status_code == 303
        assert done.headers["location"] == f"/approvals?done=denied%3A{call['id']}"
        after = await browser.get(done.headers["location"])
        assert "Denied" in after.text

    final = (await api(gateway, "GET", f"/approvals/api/calls/{call['id']}")).json()
    assert (final["status"], final["decided_by"], final["decision_reason"]) == (
        "denied",
        "alice",
        "duplicate",
    )


# -- limits ----------------------------------------------------------------------------------------


async def test_holds_are_refused_when_no_one_can_approve(finance_url: str) -> None:
    """A pipeline that holds calls on a gateway without approvals fails closed."""
    config = make_config({"finance": finance_url}, auth=AUTH)
    with running_gateway(config, [PolicyStage(RulePolicy.load(POLICY))]) as gateway:
        async with httpx2.AsyncClient(timeout=30) as http:
            _, response = await RawSession(http, gateway.url("finance"), AP, modern=True).request(
                "tools/call", {"name": "transfer_funds", "arguments": transfer(amount="18450.00")}
            )
    result = answer_of(response)["result"]
    assert result["isError"] is True
    assert "but this gateway has no approvals configured" in result["content"][0]["text"]


async def test_an_agent_cannot_pile_up_held_calls_and_undecided_ones_expire(finance_url: str) -> None:
    config = make_config(
        {"finance": finance_url},
        auth=AUTH,
        stages=[{"type": "policy", "file": str(POLICY)}],
        approvals={**FAST, "max_pending_per_agent": 1, "ttl_s": 1.5},
    )
    with running_gateway(config, approval_store=MemoryApprovalStore()) as gateway:
        async with httpx2.AsyncClient(timeout=30) as http:
            session = RawSession(http, gateway.url("finance"), AP, modern=True)
            arguments = {"name": "transfer_funds", "arguments": transfer(amount="18450.00")}
            _, first = await session.request("tools/call", arguments)
            _, second = await session.request("tools/call", arguments)
            await anyio.sleep(1.6)
            token = events(first)[0].id or ""
            expired = await http.get(
                gateway.url("finance"), headers=modern_headers(AP, **{"last-event-id": token})
            )
    refusal = answer_of(second)["result"]["content"][0]["text"]
    assert "too many of this agent's calls are already waiting (the limit is 1)" in refusal
    answer = answer_of(expired)["result"]
    assert answer["isError"] is True
    assert answer["content"][0]["text"].startswith("Denied at approval: nobody decided this call")
    assert answer_of(expired)["result"] is not None
    assert jsonrpc.APPROVAL_DENIED == -32093


async def test_the_cli_lists_and_decides_held_calls(approving: Approving, tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from mcp_customs.cli import app as cli

    reference = memo()
    async with httpx2.AsyncClient(timeout=30) as http:
        await RawSession(http, approving.gateway.url("finance"), AP, modern=True).request(
            "tools/call", {"name": "transfer_funds", "arguments": transfer(amount="18450.00", memo=reference)}
        )
    call = await pending_call(approving.gateway, reference)
    token_file = tmp_path / "approver.jwt"
    token_file.write_text(APPROVER)
    common = ["--url", approving.gateway.base, "--token-file", str(token_file)]
    runner = CliRunner()

    listed = await anyio.to_thread.run_sync(lambda: runner.invoke(cli, ["approvals", "list", *common]))
    assert listed.exit_code == 0, listed.output
    assert f"{call['id']}  pending   transfer_funds on finance for ap-agent" in listed.output
    assert f'"memo": "{reference}"' in listed.output

    denied = await anyio.to_thread.run_sync(
        lambda: runner.invoke(cli, ["approvals", "deny", call["id"], "--reason", "duplicate", *common])
    )
    assert denied.exit_code == 0, denied.output
    assert "denied by alice" in denied.output
    again = await anyio.to_thread.run_sync(
        lambda: runner.invoke(cli, ["approvals", "approve", call["id"], *common])
    )
    assert again.exit_code == 2
    assert "409: the call is already denied" in again.output
    no_token = await anyio.to_thread.run_sync(
        lambda: runner.invoke(cli, ["approvals", "list", "--url", approving.gateway.base], env={})
    )
    assert no_token.exit_code == 2
