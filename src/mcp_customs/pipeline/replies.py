"""Replies the gateway writes itself, shaped for the protocol revision in use.

A stage that stops a call answers in place of the server, so its answer must
be one the client accepts: from 2026-07-28 every result carries
``resultType``, which earlier revisions do not define.
"""

from typing import Any

from mcp_customs.jsonrpc import JSONObject, error_object
from mcp_customs.pipeline.base import ClientMessageContext, Respond
from mcp_customs.proxy.routing import is_modern


def result_reply(ctx: ClientMessageContext, result: JSONObject) -> Respond:
    body = dict(result)
    if is_modern(ctx.exchange.protocol_version):
        body.setdefault("resultType", "complete")
    return Respond({"jsonrpc": "2.0", "id": ctx.message.id, "result": body})


def tool_error_reply(ctx: ClientMessageContext, text: str) -> Respond:
    """A failed tool call the model can read and recover from, rather than a protocol error."""
    return result_reply(ctx, {"content": [{"type": "text", "text": text}], "isError": True})


def error_reply(ctx: ClientMessageContext, code: int, message: str, data: Any = None) -> Respond:
    return Respond(error_object(ctx.message.id, code, message, data))
