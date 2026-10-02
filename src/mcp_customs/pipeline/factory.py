"""Building the pipeline from configuration: one config entry per stage, in order."""

from collections.abc import Sequence

from mcp_customs.config import StageConfig
from mcp_customs.pipeline.base import Pipeline, Stage
from mcp_customs.pipeline.policy import PolicyStage
from mcp_customs.policy.engine import RulePolicy


def build_stage(config: StageConfig) -> Stage:
    match config.type:
        case "policy":
            return PolicyStage(RulePolicy.load(config.file))


def build_pipeline(configs: Sequence[StageConfig]) -> Pipeline:
    """Load every stage now, so a broken policy file stops the gateway at start-up."""
    return Pipeline([build_stage(config) for config in configs])
