import pytest
from starlette.datastructures import Headers

from mcp_customs.jsonrpc import parse_message
from mcp_customs.pipeline import (
    CONTINUE,
    Approval,
    ClientMessageContext,
    ClientOutcome,
    Exchange,
    Hold,
    Pipeline,
    Replace,
    Respond,
    ServerMessageContext,
    ServerOutcome,
    Stage,
    result_reply,
    tool_error_reply,
)
from mcp_customs.pipeline.base import InvalidReplacementError, StageFailedError

CALL = (
    b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_doc","arguments":{"doc_id":"a"}}}'
)
ANSWER = b'{"jsonrpc":"2.0","id":1,"result":{"content":[]}}'


def exchange(protocol_version: str | None = "2025-11-25") -> Exchange:
    return Exchange("workspace", "POST", Headers(), protocol_version, None)


def client_ctx(body: bytes = CALL, protocol_version: str | None = "2025-11-25") -> ClientMessageContext:
    return ClientMessageContext(exchange(protocol_version), parse_message(body))


def server_ctx(body: bytes = ANSWER) -> ServerMessageContext:
    return ServerMessageContext(exchange(), parse_message(body), parse_message(CALL))


class Recorder(Stage):
    def __init__(self, label: str, log: list[str], outcome: ClientOutcome = CONTINUE) -> None:
        self.label, self.log, self.outcome = label, log, outcome

    async def on_client_message(self, ctx: ClientMessageContext) -> ClientOutcome:
        self.log.append(f"{self.label}:{ctx.message.params['arguments']['doc_id']}")
        return self.outcome

    async def on_server_message(self, ctx: ServerMessageContext) -> ServerOutcome:
        self.log.append(f"{self.label}:answer")
        return CONTINUE


def with_doc(doc_id: str) -> dict[str, object]:
    raw = parse_message(CALL).raw
    return {**raw, "params": {**raw["params"], "arguments": {"doc_id": doc_id}}}


@pytest.mark.anyio
async def test_empty_pipeline_is_falsy_and_continues() -> None:
    pipeline = Pipeline()
    assert not pipeline
    assert await pipeline.client_message(client_ctx()) is CONTINUE
    assert await pipeline.server_message(server_ctx()) is CONTINUE


@pytest.mark.anyio
async def test_stages_run_in_order_and_see_earlier_replacements() -> None:
    log: list[str] = []
    pipeline = Pipeline([Recorder("one", log, Replace(with_doc("b"))), Recorder("two", log)])
    outcome = await pipeline.client_message(client_ctx())
    assert log == ["one:a", "two:b"]
    assert outcome == Replace(with_doc("b"))
    await pipeline.server_message(server_ctx())
    assert log[-2:] == ["one:answer", "two:answer"]


@pytest.mark.anyio
async def test_respond_stops_the_pipeline() -> None:
    log: list[str] = []
    reply = {"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": "no"}}
    pipeline = Pipeline([Recorder("one", log, Respond(reply)), Recorder("two", log)])
    assert await pipeline.client_message(client_ctx()) == Respond(reply, stage="stage")
    assert log == ["one:a"]


@pytest.mark.anyio
async def test_hold_stops_the_pipeline_until_approved() -> None:
    log: list[str] = []
    pipeline = Pipeline([Recorder("one", log, Hold("needs a human", "r1")), Recorder("two", log)])
    assert await pipeline.client_message(client_ctx()) == Hold("needs a human", "r1", stage="stage")
    assert log == ["one:a"]


@pytest.mark.anyio
async def test_an_approved_call_runs_every_stage_and_records_the_approver() -> None:
    log: list[str] = []
    pipeline = Pipeline([Recorder("one", log, Hold("needs a human")), Recorder("two", log)])
    ctx = ClientMessageContext(exchange(), parse_message(CALL), approval=Approval("h1", "alice"))
    assert await pipeline.client_message(ctx) is CONTINUE
    assert log == ["one:a", "two:a"]
    assert ctx.annotations["stage"] == {"approved_by": "alice"}


@pytest.mark.anyio
async def test_approval_waives_holds_but_not_denials() -> None:
    reply = {"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": "no"}}
    pipeline = Pipeline([Recorder("one", [], Hold("needs a human")), Recorder("two", [], Respond(reply))])
    ctx = ClientMessageContext(exchange(), parse_message(CALL), approval=Approval("h1", "alice"))
    assert await pipeline.client_message(ctx) == Respond(reply, stage="stage")


@pytest.mark.anyio
async def test_only_a_request_can_be_held() -> None:
    class HoldsEverything(Stage):
        name = "holder"

        async def on_client_message(self, ctx: ClientMessageContext) -> ClientOutcome:
            return Hold("no")

    notification = parse_message(b'{"jsonrpc":"2.0","method":"notifications/initialized"}')
    with pytest.raises(StageFailedError, match="holder"):
        await Pipeline([HoldsEverything()]).client_message(ClientMessageContext(exchange(), notification))


@pytest.mark.anyio
async def test_stage_exceptions_name_the_stage() -> None:
    class Broken(Stage):
        name = "broken"

        async def on_client_message(self, ctx: ClientMessageContext) -> ClientOutcome:
            raise RuntimeError("bug")

    with pytest.raises(StageFailedError, match="broken"):
        await Pipeline([Broken()]).client_message(client_ctx())


@pytest.mark.parametrize(
    "replacement",
    [
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "read_doc"}},
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "send_email"}},
        {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "read_doc"}},
    ],
    ids=["id", "method", "tool", "kind"],
)
@pytest.mark.anyio
async def test_client_replacements_may_not_reroute(replacement: dict[str, object]) -> None:
    with pytest.raises(InvalidReplacementError):
        await Pipeline([Recorder("r", [], Replace(replacement))]).client_message(client_ctx())


class ServerReplacer(Stage):
    def __init__(self, replacement: dict[str, object]) -> None:
        self.replacement = replacement

    async def on_server_message(self, ctx: ServerMessageContext) -> ServerOutcome:
        return Replace(self.replacement)


@pytest.mark.anyio
async def test_server_replacements_may_turn_a_result_into_an_error() -> None:
    error = {"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": "withheld"}}
    assert await Pipeline([ServerReplacer(error)]).server_message(server_ctx()) == Replace(error)


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        (ANSWER, {"jsonrpc": "2.0", "id": 2, "result": {}}),
        (ANSWER, {"jsonrpc": "2.0", "method": "notifications/message"}),
        (b'{"jsonrpc":"2.0","method":"notifications/progress"}', {"jsonrpc": "2.0", "method": "other"}),
    ],
    ids=["answer-id", "answer-kind", "notification-method"],
)
@pytest.mark.anyio
async def test_server_replacements_may_not_reroute(original: bytes, replacement: dict[str, object]) -> None:
    with pytest.raises(InvalidReplacementError):
        await Pipeline([ServerReplacer(replacement)]).server_message(server_ctx(original))


@pytest.mark.parametrize(("version", "tagged"), [("2026-07-28", True), ("2025-11-25", False), (None, False)])
def test_replies_follow_the_protocol_revision(version: str | None, tagged: bool) -> None:
    reply = tool_error_reply(client_ctx(protocol_version=version), "denied")
    result = reply.message["result"]
    assert result["isError"] is True
    assert ("resultType" in result) is tagged
    assert result_reply(client_ctx(protocol_version=version), {"resultType": "x"}).message["result"] == {
        "resultType": "x"
    }
