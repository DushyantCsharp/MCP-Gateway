"""Building the pipeline from configuration: one config entry per stage, in order."""

from collections.abc import Sequence

from mcp_customs.config import (
    ConfigError,
    InjectionStageConfig,
    PolicyStageConfig,
    RedactionStageConfig,
    StageConfig,
)
from mcp_customs.detectors import Calibrated, Detector
from mcp_customs.detectors.hidden import HiddenTextDetector, LayeredDetector
from mcp_customs.detectors.sensitive import SensitiveScanner
from mcp_customs.pipeline.base import Pipeline, Stage
from mcp_customs.pipeline.injection import InjectionStage
from mcp_customs.pipeline.policy import PolicyStage
from mcp_customs.pipeline.redaction import RedactionStage
from mcp_customs.policy.engine import RulePolicy


def build_stage(config: StageConfig) -> Stage:
    match config:
        case PolicyStageConfig():
            return PolicyStage(RulePolicy.load(config.file))
        case InjectionStageConfig():
            detector: Detector = HiddenTextDetector()
            if config.detector != "hidden":
                from mcp_customs.detectors.classifier import OnnxClassifier

                classifier = OnnxClassifier(threads=1, max_chars=config.max_chars)
                try:
                    classifier.load()  # downloads the model on first start, and fails fast if it cannot
                except ImportError as exc:
                    raise ConfigError(
                        f"the {config.detector!r} injection detector needs the classifier extra "
                        "(pip install 'mcp-customs[classifier]'); detector: hidden needs nothing"
                    ) from exc
                except Exception as exc:  # a download or model error, at start-up only
                    raise ConfigError(
                        f"cannot load the injection classifier {classifier.model}: {exc}"
                    ) from exc
                calibrated = Calibrated(classifier, config.classifier_threshold)
                detector = (
                    calibrated if config.detector == "classifier" else LayeredDetector([detector, calibrated])
                )
            return InjectionStage(
                detector, mode=config.mode, threshold=config.threshold, threads=config.threads
            )
        case RedactionStageConfig():
            scanner = SensitiveScanner(sorted({*config.requests, *config.responses}), allow=config.allow)
            return RedactionStage(
                scanner, requests=config.requests, responses=config.responses, mode=config.mode
            )


def build_pipeline(configs: Sequence[StageConfig]) -> Pipeline:
    """Load every stage now, so a broken policy file stops the gateway at start-up."""
    return Pipeline([build_stage(config) for config in configs])
