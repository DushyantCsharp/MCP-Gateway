"""Where the text a model reads lives inside MCP results and requests."""

from collections.abc import Iterator
from typing import Any

type Path = tuple[str | int, ...]


def text_fields(result: Any, method: str) -> Iterator[tuple[Path, str]]:
    """Every string in a result that a model would read, with where it lives."""
    if not isinstance(result, dict):
        return
    if method == "tools/call":
        yield from _content(result.get("content"), ("content",))
        yield from _strings(result.get("structuredContent"), ("structuredContent",))
    elif method == "resources/read":
        for index, item in enumerate(result.get("contents") or []):
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                yield ("contents", index, "text"), item["text"]
    elif method == "prompts/get":
        for index, message in enumerate(result.get("messages") or []):
            if isinstance(message, dict):
                yield from _content([message.get("content")], ("messages", index, "content"), single=True)


def _content(blocks: Any, base: Path, *, single: bool = False) -> Iterator[tuple[Path, str]]:
    for index, block in enumerate(blocks if isinstance(blocks, list) else []):
        where = base if single else (*base, index)
        if not isinstance(block, dict):
            continue
        if isinstance(block.get("text"), str):
            yield (*where, "text"), block["text"]
        resource = block.get("resource")
        if isinstance(resource, dict) and isinstance(resource.get("text"), str):
            yield (*where, "resource", "text"), resource["text"]


def _strings(value: Any, base: Path) -> Iterator[tuple[Path, str]]:
    if isinstance(value, str):
        yield base, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _strings(item, (*base, key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _strings(item, (*base, index))


def set_at(container: Any, path: Path, value: str) -> None:
    for step in path[:-1]:
        container = container[step]
    container[path[-1]] = value
