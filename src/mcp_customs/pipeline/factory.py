"""Building the pipeline from configuration: one config entry per stage, in order."""

from collections.abc import Sequence

from mcp_customs.config import InjectionStageConfig, PolicyStageConfig, StageConfig
from mcp_customs.pipeline.base import Pipeline, Stage
from mcp_customs.pipeline.injection import InjectionStage
from mcp_customs.pipeline.policy import PolicyStage
from mcp_customs.policy.engine import RulePolicy


def build_stage(config: StageConfig) -> Stage:
    match config:
        case PolicyStageConfig():
            return PolicyStage(RulePolicy.load(config.file))
        case InjectionStageConfig():
            from mcp_customs.detectors.classifier import OnnxClassifier

            detector = OnnxClassifier(threads=1)
            detector.load()  # downloads the model on first start, and fails fast if it cannot
            return InjectionStage(
                detector, mode=config.mode, threshold=config.threshold, threads=config.threads
            )


def build_pipeline(configs: Sequence[StageConfig]) -> Pipeline:
    """Load every stage now, so a broken policy file stops the gateway at start-up."""
    return Pipeline([build_stage(config) for config in configs])
