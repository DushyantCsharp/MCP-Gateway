"""Local MCP servers behind the gateway, and stdio-only clients in front of it.

A ``command`` upstream is launched by the gateway, one process per client
session, and reached over stdin and stdout; clients use it like any other
upstream. ``customs stdio`` does the reverse for clients that can only launch
local servers: it relays their stdio to the gateway over HTTP.
"""

import os
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import anyio
import pytest
from mcp import Client, MCPError
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp_types import LoggingMessageNotificationParams

from mcp_customs import jsonrpc
from mcp_customs.pipeline.policy import PolicyStage
from mcp_customs.policy import PolicyDocument, RulePolicy
from tests.contract.conftest import Gateway, make_config, running_gateway
from tests.support.clients import TEST_AUDIENCE, TEST_SECRET, mcp_client, mint

pytestmark = [pytest.mark.anyio, pytest.mark.contract]

ROOT = Path(__file__).parents[2]
LOCAL = {
    "command": [sys.executable, "-m", "tests.support.stdio_server"],
    "cwd": str(ROOT),
    "env": {"LOCAL_SETTING": "configured"},
}
PROBE = "CUSTOMS_TEST_GATEWAY_SECRET"


@pytest.fixture(scope="module")
def gateway(workspace_url: str) -> Iterator[Gateway]:
    os.environ[PROBE] = "must-not-leak"  # in the gateway's environment, as its real secrets are
    try:
        config = make_config({"local": LOCAL, "workspace": workspace_url})
        with running_gateway(config) as gw:
            yield gw
    finally:
        del os.environ[PROBE]


def text_of(result: Any) -> str:
    return str(result.content[0].model_dump()["text"])


async def test_a_local_server_works_through_the_gateway(mode: str, gateway: Gateway) -> None:
    async with Client(gateway.url("local"), mode=mode) as client:
        tools = {tool.name for tool in (await client.list_tools()).tools}
        echoed = await client.call_tool("echo", {"text": "through the gateway"})
    assert tools == {"echo", "pid", "env_names", "count", "crash"}
    assert text_of(echoed) == "through the gateway"


async def test_each_session_gets_its_own_process(gateway: Gateway) -> None:
    async with (
        Client(gateway.url("local"), mode="legacy") as first,
        Client(gateway.url("local"), mode="legacy") as second,
    ):
        ids = [text_of(await client.call_tool("pid", {})) for client in (first, first, second)]
    assert ids[0] == ids[1] != ids[2]


async def test_the_local_server_never_sees_the_gateways_secrets(gateway: Gateway) -> None:
    async with Client(gateway.url("local"), mode="legacy") as client:
        result = await client.call_tool("env_names", {})
    names = result.structured_content["result"] if result.structured_content else []
    assert PROBE not in names
    assert "LOCAL_SETTING" in names
    assert "PATH" in names


async def test_progress_and_logs_reach_the_request_they_belong_to(gateway: Gateway) -> None:
    steps: list[float] = []
    logs: list[Any] = []

    async def on_progress(progress: float, total: float | None, message: str | None) -> None:
        steps.append(progress)

    async def on_log(params: LoggingMessageNotificationParams) -> None:
        logs.append(params.data)

    async with Client(gateway.url("local"), mode="legacy", logging_callback=on_log) as client:
        result = await client.call_tool("count", {"steps": 3}, progress_callback=on_progress)
    assert text_of(result) == "counted to 3"
    assert steps == [1, 2, 3]
    assert "counted" in str(logs)


async def test_a_crashed_server_is_an_error_not_a_hang(gateway: Gateway) -> None:
    async with Client(gateway.url("local"), mode="legacy") as client:
        with anyio.fail_after(10), pytest.raises(MCPError) as crashed:
            await client.call_tool("crash", {})
    assert crashed.value.code == jsonrpc.UPSTREAM_UNAVAILABLE
    assert "exited" in str(crashed.value)


async def test_ending_the_session_ends_its_process(gateway: Gateway) -> None:
    async with Client(gateway.url("local"), mode="legacy") as client:
        pid = int(text_of(await client.call_tool("pid", {})))
        os.kill(pid, 0)  # alive while the session is
    with anyio.fail_after(10):
        while True:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            await anyio.sleep(0.05)


async def test_policy_and_identity_apply_to_local_servers() -> None:
    document = PolicyDocument.model_validate(
        {
            "version": 1,
            "rules": [{"id": "echo-only", "effect": "allow", "agents": ["dev"], "tools": ["echo"]}],
        }
    )
    config = make_config({"local": LOCAL}, auth={"jwt": {"audience": TEST_AUDIENCE, "secret": TEST_SECRET}})
    with running_gateway(config, [PolicyStage(RulePolicy(document))]) as gw:
        async with mcp_client(gw.url("local"), token=mint("dev"), mode="legacy") as client:
            listed = [tool.name for tool in (await client.list_tools()).tools]
            refused = await client.call_tool("env_names", {})
    assert listed == ["echo"]
    assert refused.is_error
    assert "Blocked by gateway policy" in text_of(refused)


def relay(url: str, token: str | None = None) -> StdioServerParameters:
    env = {**os.environ, **({"CUSTOMS_TOKEN": token} if token else {})}
    return StdioServerParameters(
        command=sys.executable, args=["-m", "mcp_customs.cli", "stdio", url], env=env, cwd=str(ROOT)
    )


@pytest.mark.parametrize("upstream", ["workspace", "local"])
async def test_a_stdio_only_client_reaches_the_gateway_through_customs_stdio(
    mode: str, gateway: Gateway, upstream: str
) -> None:
    with anyio.fail_after(60):
        async with Client(stdio_client(relay(gateway.url(upstream))), mode=mode) as client:
            tools = {tool.name for tool in (await client.list_tools()).tools}
            if upstream == "local":
                result = await client.call_tool("echo", {"text": "relayed"})
                assert text_of(result) == "relayed"
    assert ("echo" if upstream == "local" else "read_doc") in tools


async def test_customs_stdio_sends_the_agents_token() -> None:
    document = PolicyDocument.model_validate(
        {"version": 1, "rules": [{"id": "dev", "effect": "allow", "agents": ["dev"], "tools": ["echo"]}]}
    )
    config = make_config({"local": LOCAL}, auth={"jwt": {"audience": TEST_AUDIENCE, "secret": TEST_SECRET}})
    with running_gateway(config, [PolicyStage(RulePolicy(document))]) as gw:
        with anyio.fail_after(60):
            async with Client(
                stdio_client(relay(gw.url("local"), token=mint("dev"))), mode="legacy"
            ) as client:
                assert [tool.name for tool in (await client.list_tools()).tools] == ["echo"]
