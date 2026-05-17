"""Fine-tune CodeBERT on D1 for the file-level classifier (paper §3.1).

This is a thin wrapper around the existing training script
``models/codebert-malware-detector/code/run.py`` that:

1. Resolves paths so the script works from the repository root.
2. Picks JSONL splits from ``data/d1/`` (produced by ``prepare_d1.py``) and
   copies them into the location expected by ``run.py``
   (``models/codebert-malware-detector/data/{train,val,test}.jsonl``).
3. Runs training with the hyperparameters specified in the paper:
   lr=2e-5, batch=16, 4 epochs, block_size=400, seed=123456.

After training, the best checkpoint is saved at::

    models/codebert-malware-detector/saved_models/codebert-finetuned/
        checkpoint-best-acc/model.bin
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

from lamps.config import (
    CODEBERT_DATA_DIR,
    CODEBERT_TRAIN_CODE_DIR,
    CodeBERTConfig,
    D1_PREPARED_DIR,
)
from lamps.utils import configure_logging, logger


def stage_dataset(src_dir: Path, dst_dir: Path) -> None:
    """Mirror ``train.jsonl``, ``val.jsonl``, ``test.jsonl`` into ``dst_dir``."""
    dst_dir.mkdir(parents=True, exist_ok=True)
    for name in ("train.jsonl", "val.jsonl", "test.jsonl"):
        src = src_dir / name
        dst = dst_dir / name
        if not src.exists():
            raise FileNotFoundError(
                f"Missing {src}. Run `python -m lamps.data.prepare_d1` first."
            )
        shutil.copyfile(src, dst)


def build_command(cfg: CodeBERTConfig, output_dir: Path) -> list[str]:
    return [
        sys.executable,
        "run.py",
        f"--output_dir={output_dir.as_posix()}",
        "--model_type=roberta",
        "--tokenizer_name=microsoft/codebert-base",
        "--model_name_or_path=microsoft/codebert-base",
        "--do_train",
        "--do_eval",
        "--do_test",
        "--train_data_file=../data/train.jsonl",
        "--eval_data_file=../data/val.jsonl",
        "--test_data_file=../data/test.jsonl",
        f"--epoch={cfg.epochs}",
        f"--block_size={cfg.block_size}",
        f"--train_batch_size={cfg.train_batch_size}",
        f"--eval_batch_size={cfg.eval_batch_size}",
        f"--learning_rate={cfg.learning_rate}",
        f"--max_grad_norm={cfg.max_grad_norm}",
        f"--weight_decay={cfg.weight_decay}",
        "--evaluate_during_training",
        f"--seed={cfg.seed}",
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=D1_PREPARED_DIR,
        help="Directory containing train/val/test JSONL files.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("../saved_models/codebert-finetuned"),
        help="Output directory for checkpoints (relative to the run.py CWD).",
    )
    parser.add_argument("--epochs", type=int, default=CodeBERTConfig.epochs)
    parser.add_argument("--seed", type=int, default=CodeBERTConfig.seed)
    args = parser.parse_args()

    configure_logging()

    logger.info("Staging dataset from %s into %s", args.data_dir, CODEBERT_DATA_DIR)
    stage_dataset(args.data_dir, CODEBERT_DATA_DIR)

    cfg = CodeBERTConfig(epochs=args.epochs, seed=args.seed)
    cmd = build_command(cfg, args.output_dir)

    logger.info("Launching training: %s", " ".join(cmd))
    return subprocess.call(cmd, cwd=CODEBERT_TRAIN_CODE_DIR)


if __name__ == "__main__":
    raise SystemExit(main())
