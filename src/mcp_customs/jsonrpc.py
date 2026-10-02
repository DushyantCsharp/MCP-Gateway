"""Strict JSON-RPC 2.0 parsing for messages crossing the gateway.

The gateway makes decisions on what it parses and forwards what the upstream
parses, so the two must agree. Lenient parsers disagree on duplicate keys
(first wins vs last wins) and on non-standard constants such as ``NaN``; a
message that relies on either could pass a policy check as one tool call and
run upstream as another. Both are rejected here rather than normalised.
"""

import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

type JSONObject = dict[str, Any]
type RequestId = str | int

PARSE_ERROR: Final = -32700
INVALID_REQUEST: Final = -32600
METHOD_NOT_FOUND: Final = -32601
INVALID_PARAMS: Final = -32602
INTERNAL_ERROR: Final = -32603
HEADER_MISMATCH: Final = -32020
"""MCP 2026-07-28: a routing header disagrees with the message body."""

# Gateway-originated errors. MCP reserves a handful of codes in the
# implementation-defined server range (-32000..-32099); these avoid them.
UPSTREAM_UNAVAILABLE: Final = -32080
UPSTREAM_TIMEOUT: Final = -32081
UPSTREAM_BAD_RESPONSE: Final = -32082


class MessageKind(StrEnum):
    REQUEST = "request"
    NOTIFICATION = "notification"
    RESPONSE = "response"
    ERROR = "error"


class JsonRpcError(ValueError):
    """A body that cannot be accepted as one JSON-RPC message."""

    def __init__(self, code: int, message: str, request_id: RequestId | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.request_id = request_id


@dataclass(frozen=True, slots=True)
class Message:
    """One validated JSON-RPC message, kept as the decoded object."""

    raw: JSONObject
    kind: MessageKind

    @property
    def id(self) -> RequestId | None:
        value = self.raw.get("id")
        return value if isinstance(value, str | int) and not isinstance(value, bool) else None

    @property
    def method(self) -> str | None:
        value = self.raw.get("method")
        return value if isinstance(value, str) else None

    @property
    def params(self) -> JSONObject:
        value = self.raw.get("params")
        return value if isinstance(value, dict) else {}

    @property
    def is_request(self) -> bool:
        return self.kind is MessageKind.REQUEST


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> JSONObject:
    obj: JSONObject = {}
    for key, value in pairs:
        if key in obj:
            raise JsonRpcError(PARSE_ERROR, f"Duplicate key {key!r} in JSON object")
        obj[key] = value
    return obj


def _reject_constant(name: str) -> Any:
    raise JsonRpcError(PARSE_ERROR, f"Non-standard JSON constant {name}")


def loads_strict(data: bytes | str) -> Any:
    """Decode RFC 8259 JSON from UTF-8, rejecting duplicate keys and NaN/Infinity."""
    try:
        text = data.decode("utf-8") if isinstance(data, bytes) else data
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant)
    except JsonRpcError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        # ValueError covers JSONDecodeError and oversized integer literals.
        raise JsonRpcError(PARSE_ERROR, "Parse error") from exc


def _valid_id(value: Any) -> bool:
    return value is None or (isinstance(value, str | int) and not isinstance(value, bool))


def classify(obj: Any) -> Message:
    """Validate the JSON-RPC 2.0 envelope of a decoded object."""
    if isinstance(obj, list):
        raise JsonRpcError(INVALID_REQUEST, "JSON-RPC batches are not supported")
    if not isinstance(obj, dict) or obj.get("jsonrpc") != "2.0":
        raise JsonRpcError(INVALID_REQUEST, "Body must be a single JSON-RPC 2.0 message object")
    has_id = "id" in obj
    request_id = obj.get("id")
    if has_id and not _valid_id(request_id):
        raise JsonRpcError(INVALID_REQUEST, "Invalid request id")
    rid = request_id if isinstance(request_id, str | int) else None

    if "method" in obj:
        if not isinstance(obj["method"], str) or "result" in obj or "error" in obj:
            raise JsonRpcError(INVALID_REQUEST, "Invalid request", rid)
        if "params" in obj and not isinstance(obj["params"], dict | list):
            raise JsonRpcError(INVALID_REQUEST, "params must be an object or array", rid)
        if not has_id:
            return Message(obj, MessageKind.NOTIFICATION)
        if request_id is None:
            raise JsonRpcError(INVALID_REQUEST, "A request id must not be null", rid)
        return Message(obj, MessageKind.REQUEST)

    if "result" in obj and "error" not in obj and has_id:
        return Message(obj, MessageKind.RESPONSE)
    if "error" in obj and "result" not in obj and has_id:
        error = obj["error"]
        if (
            isinstance(error, dict)
            and isinstance(error.get("code"), int)
            and isinstance(error.get("message"), str)
        ):
            return Message(obj, MessageKind.ERROR)
    raise JsonRpcError(INVALID_REQUEST, "Not a JSON-RPC request, notification or response", rid)


def parse_message(data: bytes | str) -> Message:
    """Strictly decode and validate one JSON-RPC message."""
    return classify(loads_strict(data))


def dumps(obj: Any) -> bytes:
    """Serialise compactly as UTF-8, the way the MCP SDKs put messages on the wire."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def error_object(request_id: RequestId | None, code: int, message: str, data: Any = None) -> JSONObject:
    error: JSONObject = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}
