"""The injection stage in a running gateway, seen by a real MCP client in both protocol eras."""

from collections.abc import Iterator

import pytest
from mcp import Client, MCPError

from customs_demo import workspace_server
from customs_demo._serve import http_app
from customs_demo.workspace_server import Document
from mcp_customs.pipeline.injection import INJECTION_BLOCKED, META_KEY, REMOVED, WARNING, InjectionStage
from tests.contract.conftest import Gateway, make_config, running_gateway
from tests.support.servers import serve_in_thread
from tests.unit.test_injection_stage import MARKER, MarkerDetector

pytestmark = [pytest.mark.anyio, pytest.mark.contract]

DOCS = [
    Document(id="clean", title="Clean", body="Quarterly numbers are on track."),
    Document(id="marked", title="Marked", body=f"Quarterly numbers. {MARKER} End of note."),
]


@pytest.fixture(scope="module")
def upstream() -> Iterator[str]:
    with serve_in_thread(http_app(workspace_server.build_server(DOCS), json_response=False)) as base:
        yield f"{base}/mcp"


@pytest.fixture(scope="module", params=["block", "flag", "strip"])
def gateway(request: pytest.FixtureRequest, upstream: str) -> Iterator[tuple[str, Gateway]]:
    mode = request.param
    stage = InjectionStage(MarkerDetector(), mode=mode)
    with running_gateway(make_config({"workspace": upstream}), [stage]) as gw:
        yield mode, gw


def texts(result: object) -> list[str]:
    return [block.text for block in getattr(result, "content", []) if hasattr(block, "text")]


async def test_clean_results_are_untouched(mode: str, gateway: tuple[str, Gateway]) -> None:
    _, gw = gateway
    async with Client(gw.url("workspace"), mode=mode) as client:
        result = await client.call_tool("read_doc", {"doc_id": "clean"})
    assert not result.is_error
    assert texts(result) == ["# Clean\n\nQuarterly numbers are on track."]


async def test_flagged_results_are_handled_per_mode(mode: str, gateway: tuple[str, Gateway]) -> None:
    stage_mode, gw = gateway
    async with Client(gw.url("workspace"), mode=mode) as client:
        result = await client.call_tool("read_doc", {"doc_id": "marked"})
    seen = texts(result)
    match stage_mode:
        case "block":
            assert result.is_error
            assert seen[0].startswith("Withheld by the gateway")
            assert MARKER not in "".join(seen)
        case "flag":
            assert not result.is_error
            assert seen[0] == WARNING
            assert MARKER in seen[1]
            assert result.meta is not None
            assert META_KEY in result.meta
        case "strip":
            assert not result.is_error
            assert MARKER not in "".join(seen)
            assert REMOVED in seen[1]


@pytest.fixture(scope="module")
def blocking(upstream: str) -> Iterator[Gateway]:
    with running_gateway(make_config({"workspace": upstream}), [InjectionStage(MarkerDetector())]) as gw:
        yield gw


async def test_blocked_prompts_are_errors(mode: str, blocking: Gateway) -> None:
    async with Client(blocking.url("workspace"), mode=mode) as client:
        index = await client.read_resource("workspace://documents")
        assert index.contents  # the index holds titles only, so it is clean
        with pytest.raises(MCPError) as caught:
            await client.get_prompt("summarise_document", {"doc_id": MARKER})
    assert caught.value.code == INJECTION_BLOCKED
