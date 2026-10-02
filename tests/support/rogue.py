"""A deliberately misbehaving upstream, for testing how the gateway fails.

The JSON-RPC method picks the misbehaviour, so one server covers every case.
"""

import json
import threading
from collections.abc import AsyncIterator
from typing import Any

import anyio
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

SSE = "text/event-stream"


def _event(payload: Any) -> bytes:
    return f"event: message\r\ndata: {json.dumps(payload)}\r\n\r\n".encode()


def _result(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


async def _stream(*chunks: bytes) -> AsyncIterator[bytes]:
    for chunk in chunks:
        yield chunk


class RogueState:
    """What the rogue upstream observed. It runs in another thread, hence a threading.Event."""

    held_stream_closed = threading.Event()


async def _hold_open(first: bytes) -> AsyncIterator[bytes]:
    try:
        yield first
        await anyio.sleep_forever()
    finally:
        RogueState.held_stream_closed.set()


async def rogue_mcp(request: Request) -> Response:
    if request.method == "GET" and request.headers.get("x-rogue") == "hold":
        note = {
            "jsonrpc": "2.0",
            "method": "notifications/message",
            "params": {"level": "info", "data": "held"},
        }
        return StreamingResponse(_hold_open(_event(note)), media_type=SSE)
    if request.method == "GET":
        note = {
            "jsonrpc": "2.0",
            "method": "notifications/message",
            "params": {"level": "info", "data": "hi"},
        }
        return StreamingResponse(_stream(_event(note)), media_type=SSE)
    if request.method == "DELETE":
        return Response(status_code=204)

    message = json.loads(await request.body())
    method, rid = message.get("method"), message.get("id")
    if rid is None:
        return Response(status_code=202)

    match method:
        case "rogue/echo_headers":
            headers = [[name, value] for name, value in request.headers.items()]
            return JSONResponse(_result(rid, {"headers": headers}))
        case "rogue/invalid_json":
            return Response(b'{"jsonrpc": "2.0", "id": 1, "result": ', media_type="application/json")
        case "rogue/duplicate_keys":
            body = (
                f'{{"jsonrpc":"2.0","id":{json.dumps(rid)},"result":{{"ok":true}},"result":{{"evil":true}}}}'
            )
            return Response(body, media_type="application/json")
        case "rogue/wrong_id":
            return JSONResponse(_result("someone-else", {}))
        case "rogue/not_jsonrpc":
            return JSONResponse({"hello": "world"})
        case "rogue/http_error_document":
            return JSONResponse({"detail": "upstream says no"}, status_code=400)
        case "rogue/too_large":
            return JSONResponse(_result(rid, {"blob": "x" * 4096}))
        case "rogue/repeated_headers":
            response = JSONResponse(_result(rid, {}))
            response.raw_headers.extend([(b"x-trace", b"one"), (b"x-trace", b"two")])
            return response
        case "rogue/sse_truncated":
            partial = b'event: message\r\ndata: {"jsonrpc":"2.0","id":'
            return StreamingResponse(_stream(partial), media_type=SSE)
        case "rogue/sse_garbage_then_answer":
            garbage = b"event: message\r\ndata: {not json}\r\n\r\n"
            return StreamingResponse(_stream(garbage, _event(_result(rid, {"ok": True}))), media_type=SSE)
        case "rogue/sse_wrong_id_then_answer":
            impostor = _event(_result("someone-else", {"evil": True}))
            return StreamingResponse(_stream(impostor, _event(_result(rid, {"ok": True}))), media_type=SSE)
        case "rogue/sse_garbage_only":
            return StreamingResponse(_stream(b"event: message\r\ndata: [1, 2\r\n\r\n"), media_type=SSE)
        case "rogue/sse_ping_then_answer":
            return StreamingResponse(
                _stream(b": ping\r\n\r\n", _event(_result(rid, {"ok": True}))), media_type=SSE
            )
        case _:
            error = {"code": -32601, "message": f"Method not found: {method}"}
            return JSONResponse({"jsonrpc": "2.0", "id": rid, "error": error}, status_code=404)


def rogue_app() -> Starlette:
    return Starlette(routes=[Route("/mcp", rogue_mcp, methods=["GET", "POST", "DELETE"])])
