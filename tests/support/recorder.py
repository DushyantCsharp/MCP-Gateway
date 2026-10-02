"""ASGI middleware that records every JSON-RPC message an upstream receives.

Wrapped around a real sample server, it is the ground truth for enforcement
tests: a call the gateway blocked must never appear here.
"""

import json
import threading
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send


class Recorder:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self._lock = threading.Lock()
        self._received: list[tuple[dict[str, str], Any]] = []

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] != "POST":
            await self.app(scope, receive, send)
            return
        chunks: list[bytes] = []
        while True:
            message = await receive()
            chunks.append(message.get("body", b""))
            if not message.get("more_body", False):
                break
        body = b"".join(chunks)
        headers = {name.decode("latin-1"): value.decode("latin-1") for name, value in scope["headers"]}
        try:
            decoded = json.loads(body)
        except ValueError:
            decoded = None
        with self._lock:
            self._received.append((headers, decoded))

        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)

    @property
    def received(self) -> list[tuple[dict[str, str], Any]]:
        with self._lock:
            return list(self._received)

    def saw(self, request_id: str) -> bool:
        return any(isinstance(body, dict) and body.get("id") == request_id for _, body in self.received)

    def headers_for(self, request_id: str) -> dict[str, str]:
        for headers, body in self.received:
            if isinstance(body, dict) and body.get("id") == request_id:
                return headers
        raise KeyError(request_id)
