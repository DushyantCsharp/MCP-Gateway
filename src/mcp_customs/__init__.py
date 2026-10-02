"""mcp-customs: a security and governance gateway for the Model Context Protocol."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("mcp-customs")
except PackageNotFoundError:  # pragma: no cover - running from a source tree without metadata
    __version__ = "0.0.0"
