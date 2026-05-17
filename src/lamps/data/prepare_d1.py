"""Convert the bundled D1 CSV into the JSONL format expected by `run.py`.

The repository ships ``Dataset/D1-6000snippets.csv``,
which is the **D1** dataset described in the paper: 6000 setup.py files
balanced 3000 malicious / 3000 benign across 6000 packages.

Output layout::

    data/d1/train.jsonl
    data/d1/val.jsonl
    data/d1/test.jsonl

Each JSONL record matches the schema consumed by the existing CodeBERT
training script (``models/codebert-malware-detector/code/run.py``)::

    {"idx": "<package>-<version>", "func": "<setup.py source>", "target": 0|1}
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from lamps.config import D1_PREPARED_DIR, D1_RAW_CSV, SplitConfig
from lamps.data.splits import package_level_split
from lamps.utils import configure_logging, logger, write_jsonl


def load_d1_csv(csv_path: Path) -> list[dict]:
    """Load the D1 CSV into a list of normalised records."""
    df = pd.read_csv(csv_path)
    expected = {"Package", "Version", "Setup.py", "Label"}
    missing = expected - set(df.columns)
    if missing:
        raise ValueError(f"D1 CSV is missing columns: {missing}")

    records: list[dict] = []
    for _, row in df.iterrows():
        package = str(row["Package"]).strip()
        version = str(row["Version"]).strip()
        setup_src = row["Setup.py"]
        if pd.isna(setup_src):
            continue
        records.append(
            {
                "idx": f"{package}-{version}",
                "package": package,
                "version": version,
                "func": str(setup_src),
                "target": int(row["Label"]),
            }
        )
    return records


def prepare(
    csv_path: Path = D1_RAW_CSV,
    output_dir: Path = D1_PREPARED_DIR,
    split: SplitConfig = SplitConfig(),
) -> dict[str, Path]:
    """Run the full preparation pipeline and return the produced file paths."""
    configure_logging()
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Loading D1 CSV from %s", csv_path)
    records = load_d1_csv(csv_path)
    logger.info("Loaded %d records", len(records))

    train, val, test = package_level_split(
        records,
        package_key="package",
        train_ratio=split.train_ratio,
        val_ratio=split.val_ratio,
        seed=split.seed,
    )
    logger.info("Split sizes -> train=%d val=%d test=%d", len(train), len(val), len(test))

    paths = {
        "train": output_dir / "train.jsonl",
        "val": output_dir / "val.jsonl",
        "test": output_dir / "test.jsonl",
    }
    write_jsonl(train, paths["train"])
    write_jsonl(val, paths["val"])
    write_jsonl(test, paths["test"])
    logger.info("Wrote JSONL splits to %s", output_dir)
    return paths


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, default=D1_RAW_CSV)
    parser.add_argument("--out", type=Path, default=D1_PREPARED_DIR)
    parser.add_argument("--seed", type=int, default=SplitConfig().seed)
    args = parser.parse_args()

    prepare(
        csv_path=args.csv,
        output_dir=args.out,
        split=SplitConfig(seed=args.seed),
    )


if __name__ == "__main__":
    main()
