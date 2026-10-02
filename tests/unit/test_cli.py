from pathlib import Path

from typer.testing import CliRunner

from mcp_customs import __version__
from mcp_customs.cli import app

runner = CliRunner()


def test_check_config_lists_routes(tmp_path: Path) -> None:
    path = tmp_path / "customs.yaml"
    path.write_text("upstreams:\n  workspace:\n    url: http://workspace:8001/mcp\n")
    result = runner.invoke(app, ["check-config", "--config", str(path)])
    assert result.exit_code == 0
    assert "/mcp/workspace -> http://workspace:8001/mcp" in result.output


def test_check_config_fails_on_bad_config(tmp_path: Path) -> None:
    path = tmp_path / "customs.yaml"
    path.write_text("upstreams: {}\n")
    result = runner.invoke(app, ["check-config", "--config", str(path)])
    assert result.exit_code == 2
    assert "error:" in result.output


def test_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.output.strip() == __version__
