from mcp_customs.proxy.headers import client_response_headers, upstream_request_headers


def test_request_headers_drop_credentials_and_hop_by_hop() -> None:
    incoming = [
        ("Host", "gateway:8000"),
        ("Authorization", "Bearer client"),
        ("Cookie", "c=1"),
        ("Origin", "http://app.example"),
        ("Connection", "keep-alive, X-Secret-Hop"),
        ("X-Secret-Hop", "1"),
        ("Transfer-Encoding", "chunked"),
        ("Content-Length", "12"),
        ("Accept-Encoding", "gzip"),
        ("X-Forwarded-For", "203.0.113.1"),
        ("Accept", "application/json, text/event-stream"),
        ("Mcp-Session-Id", "s1"),
        ("Mcp-Param-Account", "ACC-1"),
        ("X-Custom", "a"),
        ("X-Custom", "b"),
    ]
    assert upstream_request_headers(incoming, {}) == [
        ("Accept", "application/json, text/event-stream"),
        ("Mcp-Session-Id", "s1"),
        ("Mcp-Param-Account", "ACC-1"),
        ("X-Custom", "a"),
        ("X-Custom", "b"),
        ("accept-encoding", "identity"),
    ]


def test_injected_headers_replace_client_headers_of_the_same_name() -> None:
    incoming = [("x-api-key", "from-client"), ("accept", "*/*")]
    assert upstream_request_headers(incoming, {"X-Api-Key": "from-config"}) == [
        ("accept", "*/*"),
        ("accept-encoding", "identity"),
        ("X-Api-Key", "from-config"),
    ]


def test_response_headers_keep_end_to_end_headers_only() -> None:
    upstream = [
        ("content-type", "text/event-stream"),
        ("content-length", "10"),
        ("content-encoding", "gzip"),
        ("mcp-session-id", "s1"),
        ("set-cookie", "lb=1"),
        ("server", "uvicorn"),
        ("date", "today"),
        ("connection", "close"),
        ("cache-control", "no-cache"),
    ]
    assert client_response_headers(upstream) == [
        ("content-type", "text/event-stream"),
        ("mcp-session-id", "s1"),
        ("cache-control", "no-cache"),
    ]
