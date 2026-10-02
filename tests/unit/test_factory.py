import pytest

from mcp_customs.config import ConfigError, InjectionStageConfig
from mcp_customs.detectors.classifier import OnnxClassifier
from mcp_customs.pipeline.factory import build_stage


def test_a_missing_classifier_extra_is_a_config_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(self: OnnxClassifier) -> None:
        raise ModuleNotFoundError("No module named 'onnxruntime'")

    monkeypatch.setattr(OnnxClassifier, "load", missing)
    with pytest.raises(ConfigError, match=r"needs the classifier extra"):
        build_stage(InjectionStageConfig(type="injection"))


def test_a_model_that_cannot_load_is_a_config_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def offline(self: OnnxClassifier) -> None:
        raise ConnectionError("no network")

    monkeypatch.setattr(OnnxClassifier, "load", offline)
    with pytest.raises(ConfigError, match=r"cannot load the injection classifier .*: no network"):
        build_stage(InjectionStageConfig(type="injection", detector="classifier"))


def test_the_hidden_detector_needs_no_model(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(OnnxClassifier, "load", lambda self: pytest.fail("the model was loaded"))
    assert build_stage(InjectionStageConfig(type="injection", detector="hidden")).name == "injection"
