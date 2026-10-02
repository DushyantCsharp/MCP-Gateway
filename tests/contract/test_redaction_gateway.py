"""Redaction through a running gateway, including rewritten arguments that clients mirror into headers."""

from collections.abc import Iterator

import httpx2
import pytest
from mcp import Client

from customs_demo import finance_server, workspace_server
from customs_demo._serve import http_app
from customs_demo.workspace_server import Document
from mcp_customs import jsonrpc
from mcp_customs.detectors.sensitive import SensitiveScanner
from mcp_customs.pipeline.redaction import RedactionStage
from tests.contract.conftest import Gateway, make_config, running_gateway
from tests.support.clients import RawSession
from tests.support.recorder import Recorder
from tests.support.servers import serve_in_thread
from tests.unit.test_sensitive import FAKE

pytestmark = [pytest.mark.anyio, pytest.mark.contract]

KEY = FAKE["aws_access_key"]
DOCS = [
    Document(id="hr", title="HR record", body="Employee card 4111 1111 1111 1111, email jane@example.com.")
]


@pytest.fixture(scope="module")
def recorded() -> Iterator[tuple[Gateway, Recorder, Recorder]]:
    workspace = Recorder(http_app(workspace_server.build_server(DOCS), json_response=False))
    finance = Recorder(http_app(finance_server.build_server(), json_response=True))
    with serve_in_thread(workspace) as ws, serve_in_thread(finance) as fin:
        stage = RedactionStage(
            SensitiveScanner(), requests=["secrets", "email"], responses=["secrets", "pii"]
        )
        config = make_config({"workspace": f"{ws}/mcp", "finance": f"{fin}/mcp"})
        with running_gateway(config, [stage]) as gw:
            yield gw, workspace, finance


async def test_results_reach_the_agent_scrubbed(
    mode: str, recorded: tuple[Gateway, Recorder, Recorder]
) -> None:
    gw, _, _ = recorded
    async with Client(gw.url("workspace"), mode=mode) as client:
        result = await client.call_tool("read_doc", {"doc_id": "hr"})
    text = result.content[0].model_dump()["text"]
    assert "Employee card [REDACTED:card], email [REDACTED:email]." in text
    assert "1111" not in text


async def test_secrets_never_reach_the_upstream(
    mode: str, recorded: tuple[Gateway, Recorder, Recorder]
) -> None:
    gw, workspace, _ = recorded
    async with Client(gw.url("workspace"), mode=mode) as client:
        await client.list_tools()
        receipt = await client.call_tool(
            "send_email", {"to": "ap@acme.example", "subject": "s", "body": f"key {KEY}"}
        )
    assert not receipt.is_error
    assert receipt.structured_content is not None
    assert receipt.structured_content["body"] == "key [REDACTED:aws_access_key]"
    assert receipt.structured_content["to"] == "[REDACTED:email]"
    assert all(KEY not in str(body) for _, body in workspace.received)


async def test_rewritten_arguments_keep_their_mirrored_headers_consistent(
    recorded: tuple[Gateway, Recorder, Recorder],
) -> None:
    """get_balance mirrors account_id into Mcp-Param-Account; the upstream refuses a mismatch."""
    gw, _, finance = recorded
    async with Client(gw.url("finance"), mode="auto") as client:
        await client.list_tools()  # the gateway learns the tool's header mapping from this answer
        result = await client.call_tool("get_balance", {"account_id": "jane@example.com"})
    assert result.is_error
    assert "Unknown account '[REDACTED:email]'" in str(result.content)  # not a header mismatch
    headers, body = finance.received[-1]
    assert body["params"]["arguments"] == {"account_id": "[REDACTED:email]"}
    assert headers["mcp-param-account"] == "[REDACTED:email]"


async def test_unknown_schemas_fail_closed() -> None:
    finance = Recorder(http_app(finance_server.build_server(), json_response=True))
    with serve_in_thread(finance) as fin:
        stage = RedactionStage(SensitiveScanner(), requests=["email"], responses=[])
        with running_gateway(make_config({"finance": f"{fin}/mcp"}), [stage]) as gw:
            async with httpx2.AsyncClient() as http:
                session = RawSession(http, gw.url("finance"), None, modern=True)
                request_id, response = await session.request(
                    "tools/call",
                    {"name": "get_balance", "arguments": {"account_id": "jane@example.com"}},
                    extra_headers={"mcp-param-account": "jane@example.com"},
                )
    assert response.status_code == 500
    assert response.json()["error"]["code"] == jsonrpc.INTERNAL_ERROR
    assert not finance.saw(request_id)
