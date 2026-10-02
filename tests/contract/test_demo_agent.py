"""Weekend 1 "done when": an agent completes a task through the gateway with zero code changes.

The same agent function runs against the servers and against the gateway; the
only thing that differs is the two URLs it is given.
"""

import httpx2
import pytest

from customs_demo.agent import AP_MAILBOX, run_task
from tests.contract.conftest import Gateway

pytestmark = [pytest.mark.anyio, pytest.mark.contract]


async def test_the_agent_completes_its_task_through_the_gateway(
    mode: str, gateway: Gateway, direct_urls: dict[str, str], workspace_url: str
) -> None:
    direct = await run_task(direct_urls["workspace"], direct_urls["finance"], mode=mode)
    proxied = await run_task(gateway.url("workspace"), gateway.url("finance"), mode=mode)

    assert (proxied.invoice_id, proxied.amount_due, proxied.available) == (
        direct.invoice_id,
        direct.amount_due,
        direct.available,
    )
    assert [step.split(" -> ")[0] for step in proxied.steps] == [
        step.split(" -> ")[0] for step in direct.steps
    ]

    async with httpx2.AsyncClient() as http:
        outbox = (await http.get(workspace_url.removesuffix("/mcp") + "/outbox")).json()
    sent = {email["message_id"]: email for email in outbox}
    assert sent[proxied.email_message_id]["to"] == AP_MAILBOX
    assert "inv-2026-091" in sent[proxied.email_message_id]["subject"]
