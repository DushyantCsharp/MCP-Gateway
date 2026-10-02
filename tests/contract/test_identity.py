"""Every request is authenticated, and a session belongs to the agent that opened it."""

from collections.abc import Iterator

import httpx2
import pytest
from mcp_types.version import LATEST_HANDSHAKE_VERSION

from customs_demo import workspace_server
from customs_demo._serve import http_app
from mcp_customs import jsonrpc
from tests.contract.conftest import Gateway, make_config, running_gateway
from tests.support.clients import ACCEPT, TEST_AUDIENCE, TEST_SECRET, RawSession, mcp_client, mint
from tests.support.recorder import Recorder
from tests.support.servers import serve_in_thread

pytestmark = [pytest.mark.anyio, pytest.mark.contract]

AUTH = {"jwt": {"audience": TEST_AUDIENCE, "secret": TEST_SECRET}}


@pytest.fixture(scope="module")
def recorded_workspace() -> Iterator[tuple[str, Recorder]]:
    recorder = Recorder(http_app(workspace_server.build_server(), json_response=False))
    with serve_in_thread(recorder) as base:
        yield f"{base}/mcp", recorder


@pytest.fixture(scope="module")
def secured(recorded_workspace: tuple[str, Recorder], rogue_url: str) -> Iterator[Gateway]:
    """Authentication on, no policy: identity alone, nothing filtered."""
    url, _ = recorded_workspace
    config = make_config({"workspace": url, "rogue": rogue_url}, auth=AUTH)
    with running_gateway(config) as gw:
        yield gw


async def post(url: str, headers: dict[str, str] | None = None) -> httpx2.Response:
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    async with httpx2.AsyncClient() as http:
        return await http.post(url, json=body, headers={"accept": ACCEPT, **(headers or {})})


async def test_requests_without_a_token_are_challenged(secured: Gateway) -> None:
    resp = await post(secured.url("workspace"))
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"] == 'Bearer realm="mcp-customs"'
    assert resp.json()["error"]["code"] == jsonrpc.UNAUTHENTICATED


async def test_unauthenticated_callers_cannot_discover_upstreams(secured: Gateway) -> None:
    assert (await post(secured.url("no-such-upstream"))).status_code == 401


@pytest.mark.parametrize(
    "token",
    [
        mint("ap-agent", secret="a-different-secret-that-is-also-long-enough"),
        mint("ap-agent", audience="some-other-service"),
        mint("ap-agent", ttl=-120),
        "not.a.jwt",
    ],
    ids=["wrong-key", "wrong-audience", "expired", "garbage"],
)
async def test_invalid_tokens_are_rejected(secured: Gateway, token: str) -> None:
    resp = await post(secured.url("workspace"), {"authorization": f"Bearer {token}"})
    assert resp.status_code == 401
    assert 'error="invalid_token"' in resp.headers["www-authenticate"]


@pytest.mark.parametrize("method", ["GET", "DELETE"])
async def test_streams_and_session_ends_need_a_token_too(secured: Gateway, method: str) -> None:
    async with httpx2.AsyncClient() as http:
        resp = await http.request(method, secured.url("workspace"), headers={"accept": "text/event-stream"})
    assert resp.status_code == 401


async def test_an_authenticated_agent_works_normally(mode: str, secured: Gateway, workspace_url: str) -> None:
    async with (
        mcp_client(secured.url("workspace"), token=mint("ap-agent"), mode=mode) as proxied,
        mcp_client(workspace_url, token=None, mode=mode) as direct,
    ):
        assert (await proxied.list_tools()) == (await direct.list_tools())
        result = await proxied.call_tool("read_doc", {"doc_id": "report-q3"})
    assert not result.is_error


async def test_the_bearer_token_is_not_passed_upstream(secured: Gateway) -> None:
    body = {"jsonrpc": "2.0", "id": 1, "method": "rogue/echo_headers"}
    headers = {"accept": ACCEPT, "authorization": f"Bearer {mint('ap-agent')}"}
    async with httpx2.AsyncClient() as http:
        resp = await http.post(secured.url("rogue"), json=body, headers=headers)
    seen = dict(resp.json()["result"]["headers"])
    assert "authorization" not in seen


async def test_sessions_are_bound_to_the_agent_that_opened_them(
    secured: Gateway, recorded_workspace: tuple[str, Recorder]
) -> None:
    _, recorder = recorded_workspace
    url = secured.url("workspace")
    async with httpx2.AsyncClient() as http:
        owner = RawSession(http, url, mint("ap-agent"), modern=False)
        await owner.open()
        assert owner.session_id is not None
        upstream_id, _, tag = owner.session_id.rpartition(".")
        assert upstream_id
        assert tag

        request_id, resp = await owner.request(
            "tools/call", {"name": "read_doc", "arguments": {"doc_id": "report-q3"}}
        )
        assert resp.status_code == 200
        assert recorder.headers_for(request_id)["mcp-session-id"] == upstream_id

        thief = RawSession(http, url, mint("intruder"), modern=False)
        thief.session_id = owner.session_id
        stolen_id, stolen = await thief.request("tools/list", {})
        assert stolen.status_code == 404
        assert stolen.json()["error"]["code"] == jsonrpc.SESSION_NOT_FOUND
        assert not recorder.saw(stolen_id)

        bare = RawSession(http, url, mint("ap-agent"), modern=False)
        bare.session_id = upstream_id  # the upstream's own id, without the gateway's tag
        _, unbound = await bare.request("tools/list", {})
        assert unbound.status_code == 404

        stream_headers = {
            "accept": "text/event-stream",
            "authorization": f"Bearer {mint('intruder')}",
            "mcp-session-id": owner.session_id,
            "mcp-protocol-version": LATEST_HANDSHAKE_VERSION,
        }
        assert (await http.get(url, headers=stream_headers)).status_code == 404

        end = {**stream_headers, "authorization": f"Bearer {mint('ap-agent')}"}
        assert (await http.delete(url, headers=end)).status_code == 200


async def test_a_refreshed_token_for_the_same_agent_keeps_its_session(secured: Gateway) -> None:
    async with httpx2.AsyncClient() as http:
        session = RawSession(http, secured.url("workspace"), mint("ap-agent", ttl=60), modern=False)
        await session.open()
        session.token = mint("ap-agent", ttl=3600, roles=("auditor",))
        _, resp = await session.request("tools/list", {})
    assert resp.status_code == 200
