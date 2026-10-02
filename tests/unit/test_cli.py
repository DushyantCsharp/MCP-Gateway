from pathlib import Path

import jwt
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


EXAMPLES = Path(__file__).parents[2] / "policies" / "examples"
SECRET = "cli-test-secret-that-is-long-enough-for-hs256"


def test_check_policy_validates_and_lists_rules() -> None:
    result = runner.invoke(app, ["check-policy", str(EXAMPLES / "finance-agent.yaml")])
    assert result.exit_code == 0
    assert "allow ap-pay-known-vendors" in result.output
    assert "deny  never-move-payroll" in result.output


def test_check_policy_decides_a_call() -> None:
    base = [
        "check-policy",
        str(EXAMPLES / "finance-agent.yaml"),
        "--upstream",
        "finance",
        "--tool",
        "transfer_funds",
    ]
    small = '{"from_account":"ACC-OPERATING","to_account":"ACC-NORTHWIND","amount":"500.00","memo":"m"}'
    allowed = runner.invoke(app, [*base, "--agent", "ap-agent", "--arguments", small])
    assert (allowed.exit_code, allowed.output.splitlines()[0]) == (
        0,
        "ALLOW: allowed by rule 'ap-pay-known-vendors'",
    )
    denied = runner.invoke(
        app, [*base, "--agent", "ap-agent", "--arguments", small.replace("500.00", "18450.00")]
    )
    assert denied.exit_code == 1
    assert "argument 'amount': max failed" in denied.output
    scoped = runner.invoke(
        app, [*base, "--agent", "ap-agent", "--arguments", small, "--scope", "mcp:finance:get_*"]
    )
    assert scoped.exit_code == 1
    anonymous = runner.invoke(app, [*base, "--arguments", small])
    assert anonymous.exit_code == 1


def test_check_policy_rejects_ambiguous_calls() -> None:
    policy = str(EXAMPLES / "finance-agent.yaml")
    assert runner.invoke(app, ["check-policy", policy, "--tool", "x"]).exit_code == 2
    assert (
        runner.invoke(
            app, ["check-policy", policy, "--upstream", "u", "--tool", "x", "--prompt", "y"]
        ).exit_code
        == 2
    )
    assert (
        runner.invoke(
            app, ["check-policy", policy, "--upstream", "u", "--tool", "x", "--arguments", "{"]
        ).exit_code
        == 2
    )


def test_check_policy_reports_invalid_policies(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("version: 1\nrules:\n  - id: r\n    effect: allow\n")
    result = runner.invoke(app, ["check-policy", str(path)])
    assert result.exit_code == 2
    assert "invalid" in result.output


def test_check_config_loads_referenced_policies(tmp_path: Path) -> None:
    path = tmp_path / "customs.yaml"
    path.write_text(
        "auth:\n  jwt:\n    audience: mcp-customs\n    secret: ${SECRET}\n"
        "stages:\n  - type: policy\n    file: policy.yaml\n"
        "upstreams:\n  workspace:\n    url: http://workspace:8001/mcp\n"
    )
    missing = runner.invoke(app, ["check-config", "--config", str(path)], env={"SECRET": SECRET})
    assert missing.exit_code == 2
    assert "cannot read policy" in missing.output
    (tmp_path / "policy.yaml").write_text((EXAMPLES / "finance-agent.yaml").read_text())
    ok = runner.invoke(app, ["check-config", "--config", str(path)], env={"SECRET": SECRET})
    assert ok.exit_code == 0
    assert "auth: JWT (shared secret), audience 'mcp-customs'" in ok.output
    assert f"stage: policy ({tmp_path / 'policy.yaml'})" in ok.output


def test_token_issue_mints_a_verifiable_token(tmp_path: Path) -> None:
    out = tmp_path / "token"
    args = ["token", "issue", "--agent", "ap-agent", "--role", "a", "--role", "b", "--scope", "mcp:w:*"]
    result = runner.invoke(
        app, [*args, "--task", "t1", "--ttl", "60", "--out", str(out)], env={"CUSTOMS_JWT_SECRET": SECRET}
    )
    assert result.exit_code == 0
    claims = jwt.decode(out.read_text(), SECRET, algorithms=["HS256"], audience="mcp-customs")
    assert (claims["sub"], claims["roles"], claims["scope"], claims["task"]) == (
        "ap-agent",
        ["a", "b"],
        "mcp:w:*",
        "t1",
    )
    assert claims["exp"] - claims["iat"] == 60


def test_token_issue_needs_a_strong_secret() -> None:
    result = runner.invoke(app, ["token", "issue", "--agent", "a"], env={"CUSTOMS_JWT_SECRET": "short"})
    assert result.exit_code == 2
