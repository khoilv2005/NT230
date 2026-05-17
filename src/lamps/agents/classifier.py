"""Classifier Agent (paper §3.1).

Wraps the fine-tuned CodeBERT classifier and exposes a per-file decision
together with a confidence score. The agent is intentionally thin: the model
performs the discriminative work, and the agent is responsible for
formatting, batching and downstream hand-off to the Verdict Agent.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from lamps.agents.extractor import ExtractedFile
from lamps.config import CodeBERTConfig, CODEBERT_BEST_CKPT
from lamps.models.codebert import CodeBERTClassifier, FilePrediction


@dataclass
class FileClassification:
    package: str
    rel_path: str
    label: str
    target: int
    score: float


class ClassifierAgent:
    """File-level malicious/benign classification using fine-tuned CodeBERT."""

    def __init__(
        self,
        checkpoint: Path | str = CODEBERT_BEST_CKPT,
        block_size: int = CodeBERTConfig.block_size,
        threshold: float = 0.5,
        device: str | None = None,
        batch_size: int = 32,
    ) -> None:
        self.classifier = CodeBERTClassifier(
            checkpoint=checkpoint,
            block_size=block_size,
            device=device,
            threshold=threshold,
        )
        self.batch_size = batch_size

    # ------------------------------------------------------------------
    def classify_files(
        self, files: Sequence[ExtractedFile]
    ) -> list[FileClassification]:
        """Classify a sequence of extracted files."""
        if not files:
            return []
        sources = [f.source for f in files]
        predictions = self.classifier.predict_iter(sources, batch_size=self.batch_size)
        return [
            FileClassification(
                package=f.package,
                rel_path=f.rel_path,
                label=p.label,
                target=p.target,
                score=p.score,
            )
            for f, p in zip(files, predictions)
        ]

    def classify_sources(
        self, sources: Iterable[str]
    ) -> list[FilePrediction]:
        """Classify raw source strings (used by the bulk evaluators)."""
        return self.classifier.predict_iter(list(sources), batch_size=self.batch_size)
