import json

import pytest

from mcp_customs import jsonrpc
from mcp_customs.jsonrpc import JsonRpcError, MessageKind, dumps, error_object, parse_message


@pytest.mark.parametrize(
    ("body", "kind"),
    [
        ({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, MessageKind.REQUEST),
        ({"jsonrpc": "2.0", "id": "a", "method": "tools/call", "params": {"name": "x"}}, MessageKind.REQUEST),
        ({"jsonrpc": "2.0", "method": "notifications/initialized"}, MessageKind.NOTIFICATION),
        ({"jsonrpc": "2.0", "id": 1, "result": {}}, MessageKind.RESPONSE),
        ({"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": "m"}}, MessageKind.ERROR),
        ({"jsonrpc": "2.0", "id": None, "error": {"code": -1, "message": "m"}}, MessageKind.ERROR),
    ],
)
def test_valid_messages_are_classified(body: object, kind: MessageKind) -> None:
    assert parse_message(json.dumps(body).encode()).kind is kind


@pytest.mark.parametrize(
    ("body", "code"),
    [
        (b"", jsonrpc.PARSE_ERROR),
        (b"{", jsonrpc.PARSE_ERROR),
        (b"\xef\xbb\xbf{}", jsonrpc.PARSE_ERROR),
        (b'{"a": 1, "a": 2}', jsonrpc.PARSE_ERROR),
        (b'{"jsonrpc":"2.0","id":1,"method":"m","params":{"x":{"y":1,"y":2}}}', jsonrpc.PARSE_ERROR),
        (b'{"jsonrpc":"2.0","id":1,"method":"m","params":{"x":Infinity}}', jsonrpc.PARSE_ERROR),
        (b"[" * 100_000, jsonrpc.PARSE_ERROR),
        (b"[]", jsonrpc.INVALID_REQUEST),
        (b'"just a string"', jsonrpc.INVALID_REQUEST),
        (b'{"id":1,"method":"m"}', jsonrpc.INVALID_REQUEST),
        (b'{"jsonrpc":"2.0","id":null,"method":"m"}', jsonrpc.INVALID_REQUEST),
        (b'{"jsonrpc":"2.0","id":1.5,"method":"m"}', jsonrpc.INVALID_REQUEST),
        (b'{"jsonrpc":"2.0","id":1,"method":7}', jsonrpc.INVALID_REQUEST),
        (b'{"jsonrpc":"2.0","id":1,"method":"m","params":"s"}', jsonrpc.INVALID_REQUEST),
        (b'{"jsonrpc":"2.0","id":1,"method":"m","result":{}}', jsonrpc.INVALID_REQUEST),
        (b'{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"m"}}', jsonrpc.INVALID_REQUEST),
        (b'{"jsonrpc":"2.0","id":1,"error":{"code":"x","message":"m"}}', jsonrpc.INVALID_REQUEST),
        (b'{"jsonrpc":"2.0","result":{}}', jsonrpc.INVALID_REQUEST),
    ],
)
def test_invalid_messages_are_rejected(body: bytes, code: int) -> None:
    with pytest.raises(JsonRpcError) as caught:
        parse_message(body)
    assert caught.value.code == code


def test_rejections_keep_the_request_id_when_known() -> None:
    with pytest.raises(JsonRpcError) as caught:
        parse_message(b'{"jsonrpc":"2.0","id":9,"method":"m","params":"s"}')
    assert caught.value.request_id == 9


def test_accessors() -> None:
    message = parse_message(b'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"t"}}')
    assert (message.id, message.method, message.params, message.is_request) == (
        3,
        "tools/call",
        {"name": "t"},
        True,
    )
    notification = parse_message(b'{"jsonrpc":"2.0","method":"n","params":[1]}')
    assert (notification.id, notification.params, notification.is_request) == (None, {}, False)


def test_dumps_is_compact_utf8() -> None:
    assert dumps({"a": "é", "b": [1, 2]}) == '{"a":"é","b":[1,2]}'.encode()
    with pytest.raises(ValueError, match="Out of range"):
        dumps({"x": float("nan")})


def test_error_object() -> None:
    assert error_object(1, -1, "m") == {"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": "m"}}
    assert error_object(None, -1, "m", {"k": 1})["error"]["data"] == {"k": 1}
