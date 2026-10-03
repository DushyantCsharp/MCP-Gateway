"""A fine-tuned classifier as a detector, run with ONNX Runtime (no PyTorch).

The default model is ProtectAI's ``deberta-v3-base-prompt-injection-v2``
(Apache-2.0), pinned to one revision so results are reproducible. It reads at
most 512 tokens, so longer text is scored in overlapping windows and the
highest score wins: an injection anywhere in a long tool output counts.

Requires the ``classifier`` extra: ``pip install mcp-customs[classifier]``.
The model (about 740 MB) is downloaded on first use into the Hugging Face cache.
"""

from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Any, Final

MODEL: Final = "protectai/deberta-v3-base-prompt-injection-v2"
REVISION: Final = "90c9989b1a342275dd0d1a95aad283c04e075671"
MAX_TOKENS: Final = 512
STRIDE: Final = 128


def budget(text: str, max_chars: int | None) -> str:
    """At most ``max_chars`` characters: the start and the end, where injected text usually sits."""
    if max_chars is None or len(text) <= max_chars:
        return text
    half = max_chars // 2
    return f"{text[:half]}\n{text[-half:]}"


@dataclass
class OnnxClassifier:
    """Scores text with an ONNX sequence classifier whose labels include ``INJECTION``."""

    model: str = MODEL
    revision: str = REVISION
    subfolder: str = "onnx"
    name: str = "classifier"
    threads: int = 1
    max_chars: int | None = None
    """Read at most this many characters: the first and last halves of a longer text."""

    @cached_property
    def _runtime(self) -> tuple[Any, Any, int]:
        import json

        import onnxruntime
        from huggingface_hub import hf_hub_download
        from tokenizers import Tokenizer

        def fetch(filename: str) -> Path:
            path = hf_hub_download(self.model, filename, subfolder=self.subfolder, revision=self.revision)
            return Path(path)

        labels = json.loads(fetch("config.json").read_text())["id2label"]
        injection = next(int(index) for index, label in labels.items() if label.upper() == "INJECTION")
        tokenizer = Tokenizer.from_file(str(fetch("tokenizer.json")))
        tokenizer.no_truncation()
        tokenizer.no_padding()
        options = onnxruntime.SessionOptions()
        options.intra_op_num_threads = self.threads
        session = onnxruntime.InferenceSession(str(fetch("model.onnx")), options)
        return tokenizer, session, injection

    def load(self) -> None:
        """Download and load the model now, rather than on the first call."""
        _ = self._runtime

    def _windows(self, ids: list[int]) -> list[list[int]]:
        """Overlapping windows that keep the first and last special tokens on every window."""
        if len(ids) <= MAX_TOKENS:
            return [ids]
        first, body, last = ids[0], ids[1:-1], ids[-1]
        size = MAX_TOKENS - 2
        starts = range(0, max(len(body) - STRIDE, 1), size - STRIDE)
        return [[first, *body[start : start + size], last] for start in starts]

    def detect(self, text: str) -> "Detection":
        import numpy as np

        tokenizer, session, injection = self._runtime
        ids = tokenizer.encode(budget(text, self.max_chars)).ids
        best = 0.0
        input_names = {node.name for node in session.get_inputs()}
        for window in self._windows(ids):
            inputs = {"input_ids": np.array([window], dtype=np.int64)}
            if "attention_mask" in input_names:
                inputs["attention_mask"] = np.ones((1, len(window)), dtype=np.int64)
            if "token_type_ids" in input_names:
                inputs["token_type_ids"] = np.zeros((1, len(window)), dtype=np.int64)
            logits = session.run(None, inputs)[0][0]
            exp = np.exp(logits - logits.max())
            best = max(best, float(exp[injection] / exp.sum()))
        return Detection(score=best, detector=self.name)


from mcp_customs.detectors.base import Detection  # noqa: E402 - after the class, for the annotation
