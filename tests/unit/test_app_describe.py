import logging
from pathlib import Path

from mcp_customs.app import describe
from mcp_customs.config import parse_config
from mcp_customs.pipeline import Pipeline
from mcp_customs.pipeline.factory import build_pipeline

POLICY = Path(__file__).parents[2] / "policies" / "examples" / "finance-agent.yaml"


def test_an_unprotected_gateway_says_so_loudly() -> None:
    config = parse_config({"upstreams": {"w": {"url": "http://w/mcp"}}})
    lines = describe(config, Pipeline(), None)
    warnings = [text for level, text in lines if level == logging.WARNING]
    assert warnings == [
        "auth: OFF - every caller is anonymous",
        "stages: NONE - calls are forwarded without any policy",
        "audit: OFF - calls are not recorded",
    ]


def test_a_protected_gateway_lists_what_it_enforces() -> None:
    config = parse_config(
        {
            "auth": {"jwt": {"audience": "mcp-customs", "jwks_url": "https://idp.example/jwks"}},
            "stages": [{"type": "policy", "file": str(POLICY)}],
            "telemetry": {"otlp_endpoint": "http://jaeger:4318"},
            "upstreams": {"w": {"url": "http://w/mcp"}, "f": {"url": "http://f/mcp"}},
        }
    )
    lines = [text for _, text in describe(config, build_pipeline(config.stages), None)]
    assert lines[0].endswith("serving /mcp/w, /mcp/f")
    assert "auth: JWT (JWKS https://idp.example/jwks), audience 'mcp-customs'" in lines
    assert "stage: policy (6 rules)" in lines
    assert "telemetry: OTLP to http://jaeger:4318/" in lines
