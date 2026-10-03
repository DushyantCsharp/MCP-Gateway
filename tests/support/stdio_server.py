"""A local MCP server that speaks over stdin and stdout, for testing command upstreams.

python -m tests.support.stdio_server
"""

import os

from mcp.server.mcpserver import Context, MCPServer


def build() -> MCPServer:
    server = MCPServer("local", version="0.1.0")

    @server.tool()
    def echo(text: str) -> str:
        """Return the text."""
        return text

    @server.tool()
    def pid() -> int:
        """This process's id: one per client session."""
        return os.getpid()

    @server.tool()
    def env_names() -> list[str]:
        """The environment variable names this process can see."""
        return sorted(os.environ)

    @server.tool()
    async def count(steps: int, ctx: Context) -> str:
        """Count to ``steps``, reporting progress and logging along the way."""
        for step in range(1, steps + 1):
            await ctx.report_progress(step, steps, f"step {step}")
        await ctx.info("counted")
        return f"counted to {steps}"

    @server.tool()
    def crash() -> str:
        """Exit at once, mid-call."""
        os._exit(3)

    return server


if __name__ == "__main__":
    build().run()
