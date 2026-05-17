"""Inference wrapper for the fine-tuned CodeBERT classifier (paper §3.1).

The model architecture matches ``models/codebert-malware-detector/code/model.py``:
``RobertaForSequenceClassification`` with one output unit followed by a sigmoid.
Loss is computed via a manual binary cross-entropy formulation during training,
but at inference time only the sigmoid probability is needed.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

import torch
import torch.nn as nn
from transformers import (
    RobertaConfig,
    RobertaForSequenceClassification,
    RobertaTokenizer,
)

from lamps.config import (
    CODEBERT_BASE,
    CODEBERT_BEST_CKPT,
    CodeBERTConfig,
)


@dataclass
class FilePrediction:
    """A per-file prediction returned by :class:`CodeBERTClassifier`."""

    label: str            # "malicious" or "benign"
    target: int           # 1 for malicious, 0 for benign
    score: float          # P(malicious) in [0, 1]


class CodeBERTBinaryClassifier(nn.Module):
    """Mirror of the training-time `Model` class for inference.

    The training script (``code/run.py``) wraps a HuggingFace
    `RobertaForSequenceClassification` with a custom forward that returns
    ``sigmoid(logits)``. We re-create the wrapper here so the saved
    state-dict (``model.bin``) loads cleanly.
    """

    def __init__(
        self,
        encoder: RobertaForSequenceClassification,
        dropout_probability: float = 0.0,
    ) -> None:
        super().__init__()
        self.encoder = encoder
        self.dropout = nn.Dropout(dropout_probability)

    def forward(self, input_ids: torch.Tensor) -> torch.Tensor:
        attention_mask = input_ids.ne(1)
        outputs = self.encoder(input_ids, attention_mask=attention_mask)[0]
        outputs = self.dropout(outputs)
        return torch.sigmoid(outputs)


class CodeBERTClassifier:
    """High-level interface for malicious/benign Python file classification.

    The classifier loads the fine-tuned checkpoint produced by the training
    pipeline and exposes single-file and batched prediction helpers.

    Example
    -------
    >>> clf = CodeBERTClassifier()
    >>> clf.predict("import os\\nos.system('rm -rf /')").label
    'malicious'
    """

    def __init__(
        self,
        checkpoint: Path | str = CODEBERT_BEST_CKPT,
        base_model: str = CODEBERT_BASE,
        block_size: int = CodeBERTConfig.block_size,
        device: str | None = None,
        threshold: float = 0.5,
    ) -> None:
        self.block_size = block_size
        self.threshold = threshold
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")

        # Build encoder with the same config as during fine-tuning
        # (single output unit for binary classification with BCE-style loss).
        self.tokenizer = RobertaTokenizer.from_pretrained(base_model)
        config = RobertaConfig.from_pretrained(base_model)
        config.num_labels = 1

        encoder = RobertaForSequenceClassification.from_pretrained(
            base_model, config=config
        )
        self.model = CodeBERTBinaryClassifier(encoder).to(self.device)

        ckpt_path = Path(checkpoint)
        if ckpt_path.exists():
            state = torch.load(ckpt_path, map_location=self.device)
            self.model.load_state_dict(state)
        else:
            # Allow the wrapper to be instantiated without a checkpoint for tests.
            # Predictions in this mode are not meaningful.
            import warnings

            warnings.warn(
                f"CodeBERT checkpoint not found at {ckpt_path}. Returning "
                "untrained predictions. Run the training pipeline first.",
                stacklevel=2,
            )

        self.model.eval()

    # ------------------------------------------------------------------
    # Encoding
    # ------------------------------------------------------------------
    def _encode(self, codes: Sequence[str]) -> torch.Tensor:
        """Encode a batch of source files using the same scheme as training."""
        input_ids: list[list[int]] = []
        for code in codes:
            normalised = " ".join(code.split())
            tokens = self.tokenizer.tokenize(normalised)[: self.block_size - 2]
            tokens = [self.tokenizer.cls_token, *tokens, self.tokenizer.sep_token]
            ids = self.tokenizer.convert_tokens_to_ids(tokens)
            ids += [self.tokenizer.pad_token_id] * (self.block_size - len(ids))
            input_ids.append(ids)
        return torch.tensor(input_ids, dtype=torch.long, device=self.device)

    # ------------------------------------------------------------------
    # Prediction
    # ------------------------------------------------------------------
    @torch.no_grad()
    def predict_batch(self, codes: Sequence[str]) -> list[FilePrediction]:
        """Classify a batch of source files."""
        if not codes:
            return []
        ids = self._encode(codes)
        probs = self.model(ids)[:, 0].detach().cpu().numpy()
        return [
            FilePrediction(
                label="malicious" if p > self.threshold else "benign",
                target=int(p > self.threshold),
                score=float(p),
            )
            for p in probs
        ]

    def predict(self, code: str) -> FilePrediction:
        """Convenience wrapper around :meth:`predict_batch` for a single file."""
        return self.predict_batch([code])[0]

    def predict_iter(
        self, codes: Iterable[str], batch_size: int = 32
    ) -> list[FilePrediction]:
        """Predict over an iterable while batching for efficiency."""
        codes = list(codes)
        out: list[FilePrediction] = []
        for i in range(0, len(codes), batch_size):
            out.extend(self.predict_batch(codes[i : i + batch_size]))
        return out
