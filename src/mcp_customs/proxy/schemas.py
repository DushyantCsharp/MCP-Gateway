"""Which tool arguments each upstream's tools mirror into ``Mcp-Param-*`` headers.

At 2026-07-28 a tool can mark arguments with ``x-mcp-header``; clients copy
those arguments into HTTP headers, and servers refuse calls whose headers and
body disagree. When a stage rewrites an argument (redaction, say), the
headers must be rewritten to match. The gateway learns each tool's mapping
from the ``tools/list`` answers it relays, and keeps the latest one.
"""

from collections.abc import Mapping
from typing import Any

from mcp.shared.inbound import find_invalid_x_mcp_header, mcp_param_headers, x_mcp_header_map

type HeaderMap = dict[tuple[str, ...], str]


class ToolSchemas:
    def __init__(self) -> None:
        self._maps: dict[tuple[str, str], HeaderMap] = {}

    def learn(self, upstream: str, result: Any) -> None:
        tools = result.get("tools") if isinstance(result, Mapping) else None
        for tool in tools if isinstance(tools, list) else []:
            if not isinstance(tool, Mapping) or not isinstance(name := tool.get("name"), str):
                continue
            schema = tool.get("inputSchema")
            if find_invalid_x_mcp_header(schema) is None:
                self._maps[(upstream, name)] = x_mcp_header_map(schema)

    def param_headers(self, upstream: str, tool: str, arguments: Any) -> dict[str, str] | None:
        """The ``Mcp-Param-*`` headers for these arguments, or ``None`` if the tool was never listed."""
        header_map = self._maps.get((upstream, tool))
        if header_map is None:
            return None
        return mcp_param_headers(header_map, arguments if isinstance(arguments, Mapping) else {})
