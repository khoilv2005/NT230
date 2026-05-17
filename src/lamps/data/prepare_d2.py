"""Loader for the D2 multi-file dataset (paper §4.2.2).

Per the paper authors, the raw D2 archive cannot be redistributed
("The authors do not have permission to share data."). This module therefore
implements the loading logic against an expected directory layout so users
can drop the data in once obtained from Ibiyo et al. (2025).

Expected layout (configurable)::

    data/d2/raw/
      <package_name>/
        <file_path>.py        # any number of .py files per package
      labels.csv              # header: package,label  (label in {0, 1})

Output layout (after running this script)::

    data/d2/files.jsonl       # one record per .py file
    data/d2/packages.jsonl    # one record per package with file ids

Each ``files.jsonl`` record has the schema::

    {
        "idx": "<package>::<relative/path/to/file.py>",
        "package": "<package_name>",
        "path": "<relative path>",
        "func": "<file source code>",
        "target": 0 | 1            # propagated from the package label
    }

The dataset preserves the natural class imbalance (274 mal / 1022 benign across
507 packages) when the source files are present; missing files are skipped
with a warning.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

from lamps.config import D2_PREPARED_DIR
from lamps.utils import configure_logging, logger, write_jsonl


D2_RAW_DEFAULT = Path("data/d2/raw")
D2_LABELS_DEFAULT = "labels.csv"


def load_labels(labels_csv: Path) -> dict[str, int]:
    """Read the package-level labels file."""
    labels: dict[str, int] = {}
    with open(labels_csv, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            labels[row["package"].strip()] = int(row["label"])
    return labels


def iter_package_files(package_dir: Path) -> list[Path]:
    """Yield .py files under a package directory in deterministic order."""
    return sorted(p for p in package_dir.rglob("*.py") if p.is_file())


def prepare(
    raw_dir: Path = D2_RAW_DEFAULT,
    output_dir: Path = D2_PREPARED_DIR,
    labels_filename: str = D2_LABELS_DEFAULT,
) -> dict[str, Path]:
    """Materialise the D2 dataset into JSONL files."""
    configure_logging()
    output_dir.mkdir(parents=True, exist_ok=True)

    labels_path = raw_dir / labels_filename
    if not labels_path.exists():
        raise FileNotFoundError(
            f"Could not find {labels_path}. Please populate {raw_dir} with the "
            "D2 dataset from Ibiyo et al. (2025) before running this script."
        )

    labels = load_labels(labels_path)
    logger.info("Loaded labels for %d packages", len(labels))

    file_records: list[dict] = []
    package_records: list[dict] = []
    skipped_packages: list[str] = []

    for package, label in sorted(labels.items()):
        package_dir = raw_dir / package
        if not package_dir.is_dir():
            skipped_packages.append(package)
            continue

        py_files = iter_package_files(package_dir)
        if not py_files:
            skipped_packages.append(package)
            continue

        file_ids: list[str] = []
        for path in py_files:
            try:
                source = path.read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                logger.warning("Could not read %s: %s", path, exc)
                continue

            rel_path = path.relative_to(package_dir).as_posix()
            file_id = f"{package}::{rel_path}"
            file_ids.append(file_id)
            file_records.append(
                {
                    "idx": file_id,
                    "package": package,
                    "path": rel_path,
                    "func": source,
                    "target": label,
                }
            )

        package_records.append(
            {
                "package": package,
                "label": label,
                "files": file_ids,
                "n_files": len(file_ids),
            }
        )

    if skipped_packages:
        logger.warning(
            "Skipped %d packages with missing or empty directories", len(skipped_packages)
        )

    files_path = output_dir / "files.jsonl"
    packages_path = output_dir / "packages.jsonl"
    write_jsonl(file_records, files_path)
    write_jsonl(package_records, packages_path)
    logger.info(
        "Wrote %d files across %d packages to %s",
        len(file_records),
        len(package_records),
        output_dir,
    )
    return {"files": files_path, "packages": packages_path}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, default=D2_RAW_DEFAULT)
    parser.add_argument("--out", type=Path, default=D2_PREPARED_DIR)
    parser.add_argument("--labels", type=str, default=D2_LABELS_DEFAULT)
    args = parser.parse_args()

    prepare(raw_dir=args.raw, output_dir=args.out, labels_filename=args.labels)


if __name__ == "__main__":
    main()
