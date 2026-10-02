"""Shared entry-point plumbing for the sample servers."""

import argparse
import os
from collections.abc import Awaitable, Callable

import uvicorn
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

type Handler = Callable[[Request], Awaitable[Response]]


def add_route(server: MCPServer, path: str, method: str, handler: Handler) -> None:
    """Register a plain HTTP route (``custom_route`` is an untyped decorator, so call it here once)."""
    server.custom_route(path, methods=[method], include_in_schema=False)(handler)


def add_health_route(server: MCPServer) -> None:
    async def healthz(_: Request) -> Response:
        return JSONResponse({"status": "ok", "server": server.name})

    add_route(server, "/healthz", "GET", healthz)


def http_app(server: MCPServer, *, json_response: bool) -> Starlette:
    """Build the Streamable HTTP app served at ``/mcp``.

    DNS-rebinding protection is left to whatever fronts the server: in the demo
    that is the gateway, which validates ``Origin`` itself and reaches the
    servers by their Compose hostnames.
    """
    return server.streamable_http_app(
        json_response=json_response,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )


def serve(server: MCPServer, *, json_response: bool, default_port: int) -> None:
    parser = argparse.ArgumentParser(description=f"Run the {server.name!r} sample MCP server.")
    parser.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", default_port)))
    args = parser.parse_args()
    uvicorn.run(http_app(server, json_response=json_response), host=args.host, port=args.port)
