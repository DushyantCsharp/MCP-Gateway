"""Which HTTP headers cross the gateway, in each direction.

Client credentials end at the gateway. ``Authorization`` and ``Cookie`` are
never forwarded upstream: passing a client's token through to a server it was
not issued for is the "token passthrough" anti-pattern the MCP security
guidance forbids. Credentials an upstream needs are configured per upstream
and injected here instead.

Everything else that is end-to-end (``Mcp-Session-Id``,
``MCP-Protocol-Version``, ``Mcp-Method``, ``Mcp-Name``, ``Mcp-Param-*``,
``Last-Event-ID``, ``Accept``, ``Content-Type`` and custom headers) is
forwarded unchanged, with duplicates and order preserved.
"""

from collections.abc import Iterable, Mapping
from typing import Final

HOP_BY_HOP: Final = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)

_REQUEST_DROP: Final = HOP_BY_HOP | {
    "host",
    "content-length",
    "accept-encoding",
    "origin",
    "authorization",
    "cookie",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
}

_RESPONSE_DROP: Final = HOP_BY_HOP | {
    "content-length",
    "content-encoding",
    "date",
    "server",
    "set-cookie",
}

type HeaderList = list[tuple[str, str]]


def _connection_tokens(headers: Iterable[tuple[str, str]]) -> set[str]:
    """Header names listed in ``Connection``, which are hop-by-hop too (RFC 9110 7.6.1)."""
    return {
        token.strip().lower()
        for name, value in headers
        if name.lower() == "connection"
        for token in value.split(",")
        if token.strip()
    }


def upstream_request_headers(incoming: Iterable[tuple[str, str]], inject: Mapping[str, str]) -> HeaderList:
    """Headers for the forwarded request.

    ``Accept-Encoding: identity`` is set so the relay always sees plain bytes
    it can inspect. Injected headers replace any same-named client header.
    """
    pairs = list(incoming)
    drop = _REQUEST_DROP | _connection_tokens(pairs) | {name.lower() for name in inject}
    out: HeaderList = [(name, value) for name, value in pairs if name.lower() not in drop]
    out.append(("accept-encoding", "identity"))
    out.extend(inject.items())
    return out


def client_response_headers(upstream: Iterable[tuple[str, str]]) -> HeaderList:
    pairs = list(upstream)
    drop = _RESPONSE_DROP | _connection_tokens(pairs)
    return [(name, value) for name, value in pairs if name.lower() not in drop]
