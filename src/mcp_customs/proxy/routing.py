"""Consistency between MCP routing headers and the message body.

MCP 2026-07-28 mirrors the method and the tool, prompt or resource name into
``Mcp-Method`` and ``Mcp-Name`` headers so that intermediaries can route
without parsing bodies. The gateway decides on the body, but anything behind
it might route on the headers, so a request whose headers say one thing and
whose body says another is refused before it is forwarded.

``Mcp-Param-*`` headers are not checked here: validating them needs the tool's
input schema, and upstream servers already reject mismatches. The gateway
never reads argument values from them.
"""

from collections.abc import Iterable, Mapping
from typing import Final

from mcp.shared.inbound import (
    MCP_METHOD_HEADER,
    MCP_NAME_HEADER,
    MCP_PROTOCOL_VERSION_HEADER,
    NAME_BEARING_METHODS,
    decode_header_value,
    find_duplicated_routing_header,
)
from mcp_types import PROTOCOL_VERSION_META_KEY
from mcp_types.version import MODERN_PROTOCOL_VERSIONS

from mcp_customs.jsonrpc import Message, MessageKind

_MODERN: Final = frozenset(MODERN_PROTOCOL_VERSIONS)


def is_modern(protocol_version: str | None) -> bool:
    """True for the stateless per-request revisions (2026-07-28 onwards)."""
    return protocol_version in _MODERN


def name_param(message: Message) -> object:
    """The tool name, prompt name or resource URI a request targets, if any."""
    method = message.method
    key = NAME_BEARING_METHODS.get(method) if method is not None else None
    return message.params.get(key) if key is not None else None


def protocol_version_of(message: Message, headers: Mapping[str, str]) -> str | None:
    """The protocol revision a message claims, from the header, the envelope or ``initialize``."""
    if header := headers.get(MCP_PROTOCOL_VERSION_HEADER):
        return header
    params = message.params
    meta = params.get("_meta")
    if isinstance(meta, dict) and isinstance(version := meta.get(PROTOCOL_VERSION_META_KEY), str):
        return version
    if message.method == "initialize" and isinstance(version := params.get("protocolVersion"), str):
        return version
    return None


def routing_header_mismatch(
    message: Message, headers: Mapping[str, str], raw_headers: Iterable[tuple[str, str]]
) -> str | None:
    """Describe the first disagreement between routing headers and body, or ``None``."""
    if (duplicated := find_duplicated_routing_header(raw_headers)) is not None:
        return f"{duplicated} header appears more than once"
    if message.kind not in (MessageKind.REQUEST, MessageKind.NOTIFICATION):
        return None

    version_header = headers.get(MCP_PROTOCOL_VERSION_HEADER)
    method_header = headers.get(MCP_METHOD_HEADER)
    modern_request = message.kind is MessageKind.REQUEST and is_modern(version_header)

    if modern_request:
        meta = message.params.get("_meta")
        envelope_version = meta.get(PROTOCOL_VERSION_META_KEY) if isinstance(meta, dict) else None
        if envelope_version is not None and envelope_version != version_header:
            return "MCP-Protocol-Version header does not match the request envelope's protocol version"
        if method_header != message.method:
            return "Mcp-Method header does not match the request body's method"
    elif method_header is not None and method_header != message.method:
        return "Mcp-Method header does not match the message body's method"

    method = message.method
    if method is None or (key := NAME_BEARING_METHODS.get(method)) is None:
        return None
    name_header = headers.get(MCP_NAME_HEADER)
    body_name = message.params.get(key)
    if body_name is None:
        return (
            f"Mcp-Name header is present but the request has no {key!r}" if name_header is not None else None
        )
    if (modern_request or name_header is not None) and decode_header_value(name_header) != body_name:
        return f"Mcp-Name header does not match the request body's {key!r}"
    return None
