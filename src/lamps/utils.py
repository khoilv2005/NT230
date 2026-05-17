"""Common utilities shared across modules."""

from __future__ import annotations

import json
import logging
import random
from pathlib import Path
from typing import Iterable, Iterator, Sequence

import numpy as np


logger = logging.getLogger("lamps")


def configure_logging(level: int = logging.INFO) -> None:
    """Configure the root LAMPS logger once."""
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        )
        logger.addHandler(handler)
        logger.setLevel(level)


def set_global_seed(seed: int) -> None:
    """Seed Python, NumPy and (if installed) PyTorch."""
    random.seed(seed)
    np.random.seed(seed)
    try:
        import torch

        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)
    except ImportError:
        pass


def read_jsonl(path: Path) -> Iterator[dict]:
    """Yield JSON objects from a JSON-lines file."""
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def write_jsonl(records: Iterable[dict], path: Path) -> None:
    """Write an iterable of dicts to a JSON-lines file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


def truncate(text: str, max_chars: int) -> str:
    """Safely truncate text without raising on None."""
    if not text:
        return ""
    return text[:max_chars]


def chunked(seq: Sequence, size: int) -> Iterator[list]:
    """Yield successive chunks of length `size` from `seq`."""
    for i in range(0, len(seq), size):
        yield list(seq[i : i + size])
