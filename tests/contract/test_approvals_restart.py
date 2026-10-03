"""Weekend 6 "done when": a consequential call waits for a human and survives a gateway restart.

An agent asks to pay an invoice over the single-approver limit. While the call
waits for a human, the gateway is stopped and a new one is started on the same
port with the same configuration: the only thing the two share is Postgres. A
human approves the call through the new gateway, and the agent's original
``call_tool`` returns the payment's receipt. The agent is the official SDK
client, unmodified; it reconnects on its own (SEP-1699 stream resumption). The
finance server must record exactly one payment.
"""

import uuid
from contextlib import ExitStack
from pathlib import Path
from typing import Any

import anyio
import httpx2
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from customs_demo import finance_server
from customs_demo._serve import http_app
from mcp_customs.app import create_app
from mcp_customs.config import GatewayConfig
from tests.contract.conftest import make_config
from tests.support.clients import TEST_AUDIENCE, TEST_SECRET, mint
from tests.support.finance_cases import transfer
from tests.support.recorder import Recorder
from tests.support.servers import free_port, serve_in_thread

pytestmark = [pytest.mark.anyio, pytest.mark.contract]

POLICY = Path(__file__).parents[2] / "policies" / "examples" / "finance-agent.yaml"
APPROVER = mint("alice", roles=("approver",), ttl=3600)


class Gateways:
    """Gateway processes, one at a time, on one port."""

    def __init__(self, config: GatewayConfig, port: int) -> None:
        self.config, self.port = config, port
        self._running: ExitStack | None = None
        self.started = 0

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> None:
        stack = ExitStack()
        stack.enter_context(serve_in_thread(create_app(self.config), port=self.port))
        self._running = stack
        self.started += 1

    def stop(self) -> None:
        if self._running is not None:
            self._running.close()
            self._running = None


async def pending(base: str, memo: str) -> dict[str, Any]:
    async with httpx2.AsyncClient(headers={"authorization": f"Bearer {APPROVER}"}) as http:
        with anyio.fail_after(15):
            while True:
                for call in (await http.get(f"{base}/approvals/api/calls")).json():
                    if call["arguments"]["memo"] == memo:
                        return dict(call)
                await anyio.sleep(0.05)


async def test_a_held_payment_survives_a_gateway_restart(mode: str, pg_dsn: str) -> None:
    finance = Recorder(http_app(finance_server.build_server(), json_response=True))
    memo = f"INV-{uuid.uuid4().hex[:10]}"
    with serve_in_thread(finance) as finance_base:
        config = make_config(
            {"finance": f"{finance_base}/mcp"},
            # Handshake-era session ids are bound with this key; without a fixed one, a restarted
            # gateway would not recognise the client's session, and its reconnect would get a 404.
            auth={"jwt": {"audience": TEST_AUDIENCE, "secret": TEST_SECRET}, "session_secret": "s" * 32},
            stages=[{"type": "policy", "file": str(POLICY)}],
            # retry_ms is the client's reconnect delay; the SDK tries twice, so the restart has ~3s.
            approvals={"dsn": pg_dsn, "stream_s": 1, "retry_ms": 1500, "poll_s": 0.2},
        )
        gateways = Gateways(config, free_port())
        gateways.start()
        results: list[Any] = []
        try:
            headers = {"authorization": f"Bearer {mint('ap-agent', ttl=3600)}"}
            async with (
                httpx2.AsyncClient(headers=headers, timeout=httpx2.Timeout(30.0, read=300.0)) as http,
                Client(
                    streamable_http_client(f"{gateways.base}/mcp/finance", http_client=http), mode=mode
                ) as client,
            ):
                await client.list_tools()

                async def pay() -> None:
                    arguments = transfer(amount="18450.00", memo=memo)
                    results.append(await client.call_tool("transfer_funds", arguments))

                async with anyio.create_task_group() as tasks:
                    tasks.start_soon(pay)
                    held = await pending(gateways.base, memo)

                    await anyio.to_thread.run_sync(gateways.stop)  # the agent's stream drops
                    assert results == []
                    await anyio.to_thread.run_sync(gateways.start)  # a new process: memory is gone

                    async with httpx2.AsyncClient(
                        headers={"authorization": f"Bearer {APPROVER}"}
                    ) as approver:
                        decision = await approver.post(
                            f"{gateways.base}/approvals/api/calls/{held['id']}/decision",
                            json={"decision": "approve", "reason": "approved after the restart"},
                        )
                    assert decision.status_code == 200, decision.text
        finally:
            await anyio.to_thread.run_sync(gateways.stop)

        async with httpx2.AsyncClient() as http:
            made = [p for p in (await http.get(f"{finance_base}/transfers")).json() if p["memo"] == memo]

    (result,) = results
    assert not result.is_error, result
    assert result.structured_content is not None
    assert len(made) == 1  # made once, by the second gateway
    assert gateways.started == 2
    calls = [
        body for _, body in finance.received if isinstance(body, dict) and body.get("method") == "tools/call"
    ]
    assert sum(1 for body in calls if body["params"]["arguments"].get("memo") == memo) == 1
