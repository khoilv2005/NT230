"""Centralised configuration for the LAMPS pipeline and experiments.

All paths are relative to the repository root unless explicitly absolute.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

DATASET_DIR = REPO_ROOT / "Dataset"
D1_RAW_CSV = DATASET_DIR / "D1-6000snippets.csv"
D1_PREPARED_DIR = REPO_ROOT / "data" / "d1"
D2_PREPARED_DIR = REPO_ROOT / "data" / "d2"

CODEBERT_MODEL_DIR = REPO_ROOT / "models" / "codebert-malware-detector"
CODEBERT_TRAIN_CODE_DIR = CODEBERT_MODEL_DIR / "code"
CODEBERT_DATA_DIR = CODEBERT_MODEL_DIR / "data"
CODEBERT_SAVED_DIR = CODEBERT_MODEL_DIR / "saved_models" / "codebert-finetuned"
CODEBERT_BEST_CKPT = CODEBERT_SAVED_DIR / "checkpoint-best-acc" / "model.bin"

DOWNLOADS_DIR = REPO_ROOT / "downloads"
EXTRACTED_DIR = REPO_ROOT / "extracted"
RESULTS_DIR = REPO_ROOT / "results"


# ---------------------------------------------------------------------------
# Model identifiers
# ---------------------------------------------------------------------------

CODEBERT_BASE = "microsoft/codebert-base"
LLAMA_DEFAULT_MODEL = os.getenv("LLAMA_MODEL_ID", "meta-llama/Meta-Llama-3-8B-Instruct")
GEMINI_DEFAULT_MODEL = os.getenv("GEMINI_MODEL", "gemini-3-flash-preview")


# ---------------------------------------------------------------------------
# Hyperparameters (paper §3.1, §4.3)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CodeBERTConfig:
    """Fine-tuning hyperparameters for the file-level classifier.

    Values follow the paper: lr=2e-5, batch=16, BCE-style loss, 4 epochs.
    Block size 400 matches the existing training scripts in the repository.
    """

    learning_rate: float = 2e-5
    train_batch_size: int = 16
    eval_batch_size: int = 64
    epochs: int = 4
    block_size: int = 400
    seed: int = 123456
    weight_decay: float = 0.0
    max_grad_norm: float = 1.0
    dropout_probability: float = 0.0


@dataclass(frozen=True)
class SplitConfig:
    """Package-level dataset split ratios.

    The paper does not pin exact ratios, so we adopt a standard 80/10/10 split.
    """

    train_ratio: float = 0.8
    val_ratio: float = 0.1
    test_ratio: float = 0.1
    seed: int = 42


@dataclass
class LampsConfig:
    """Runtime configuration consumed by the pipeline and experiments."""

    codebert_model_dir: Path = CODEBERT_MODEL_DIR
    codebert_block_size: int = 400
    decision_threshold: float = 0.5
    extract_dir: Path = EXTRACTED_DIR
    download_dir: Path = DOWNLOADS_DIR
    use_llm_for_extractor: bool = True
    use_llm_for_verdict: bool = True
    seeds: list[int] = field(default_factory=lambda: [13, 42, 123, 2025, 31337])


def ensure_dirs() -> None:
    """Create canonical output directories if they do not yet exist."""
    for directory in [D1_PREPARED_DIR, D2_PREPARED_DIR, DOWNLOADS_DIR,
                      EXTRACTED_DIR, RESULTS_DIR]:
        directory.mkdir(parents=True, exist_ok=True)
