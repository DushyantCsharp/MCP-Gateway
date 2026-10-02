from pathlib import Path

import pytest

from mcp_customs.config import ConfigError, expand_env, load_config, parse_config


def test_minimal_config_gets_defaults() -> None:
    config = parse_config({"upstreams": {"workspace": {"url": "http://workspace:8001/mcp"}}})
    assert config.server.host == "127.0.0.1"
    assert config.server.port == 8000
    assert config.security.allowed_origins == []
    assert str(config.upstreams["workspace"].url) == "http://workspace:8001/mcp"


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"upstreams": {}},
        {"upstreams": {"Bad Name": {"url": "http://x/mcp"}}},
        {"upstreams": {"ok": {"url": "ftp://x/mcp"}}},
        {"upstreams": {"ok": {"url": "http://x/mcp", "headers": {"Host": "evil"}}}},
        {"upstreams": {"ok": {"url": "http://x/mcp", "read_timeout_s": 0}}},
        {"upstreams": {"ok": {"url": "http://x/mcp"}}, "unexpected": True},
    ],
    ids=["empty", "no-upstreams", "bad-name", "bad-scheme", "reserved-header", "zero-timeout", "unknown-key"],
)
def test_invalid_configs_are_rejected(data: dict[str, object]) -> None:
    with pytest.raises(ConfigError):
        parse_config(data)


def test_environment_references_are_expanded() -> None:
    env = {"TOKEN": "s3cret", "HOST": "finance"}
    data = {"a": "Bearer ${TOKEN}", "b": ["http://${HOST}:${PORT:-8002}/mcp"], "c": 5}
    assert expand_env(data, env) == {"a": "Bearer s3cret", "b": ["http://finance:8002/mcp"], "c": 5}


def test_missing_environment_references_are_errors() -> None:
    with pytest.raises(ConfigError, match="MISSING"):
        expand_env("${MISSING}", {})


def test_expanded_values_cannot_inject_structure(tmp_path: Path) -> None:
    path = tmp_path / "customs.yaml"
    path.write_text("upstreams:\n  w:\n    url: http://w/mcp\n    headers:\n      X-Token: ${TOKEN}\n")
    config = load_config(path, {"TOKEN": "a\nupstreams: {}"})
    assert config.upstreams["w"].headers == {"X-Token": "a\nupstreams: {}"}


@pytest.mark.parametrize(
    ("content", "message"),
    [("upstreams: [", "not valid YAML"), ("- a list", "mapping at the top level")],
)
def test_unreadable_files_are_reported(tmp_path: Path, content: str, message: str) -> None:
    path = tmp_path / "customs.yaml"
    path.write_text(content)
    with pytest.raises(ConfigError, match=message):
        load_config(path)


def test_missing_files_are_reported(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(tmp_path / "absent.yaml")
