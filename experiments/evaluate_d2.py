"""Evaluate LAMPS on D2 (paper §5.2 / §5.3).

D2 is the multi-file dataset (1296 .py files across 507 packages, with the
natural class imbalance preserved). The full LAMPS pipeline is exercised:

* Classifier Agent classifies every Python file in every package.
* Verdict Agent applies the conservative aggregation rule: a package is
  malicious if at least one of its files is flagged.

The dataset is loaded from the JSONL files produced by ``prepare_d2.py``::

    data/d2/files.jsonl       # one record per .py file
    data/d2/packages.jsonl    # one record per package with file ids

Per-file predictions and per-package verdicts are written to ``results/d2/``.

Run::

    python -m experiments.evaluate_d2 --output results/d2
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

from lamps.agents.classifier import ClassifierAgent, FileClassification
from lamps.agents.extractor import ExtractedFile
from lamps.agents.verdict import VerdictAgent
from lamps.config import CODEBERT_BEST_CKPT, D2_PREPARED_DIR, RESULTS_DIR
from lamps.evaluation.metrics import classification_report, format_report
from lamps.utils import configure_logging, logger, read_jsonl, set_global_seed


def load_d2(data_dir: Path) -> tuple[list[dict], list[dict]]:
    files_path = data_dir / "files.jsonl"
    packages_path = data_dir / "packages.jsonl"
    if not files_path.exists() or not packages_path.exists():
        raise FileNotFoundError(
            f"D2 not prepared. Expected {files_path} and {packages_path}. "
            "Run `python -m lamps.data.prepare_d2` first."
        )
    return list(read_jsonl(files_path)), list(read_jsonl(packages_path))


def group_files(file_records: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for record in file_records:
        grouped[record["package"]].append(record)
    return grouped


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=D2_PREPARED_DIR)
    parser.add_argument("--checkpoint", type=Path, default=CODEBERT_BEST_CKPT)
    parser.add_argument("--output", type=Path, default=RESULTS_DIR / "d2")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument(
        "--explain",
        action="store_true",
        help="Use Gemini for Verdict Agent rationales (slow; requires API key).",
    )
    args = parser.parse_args()

    configure_logging()
    set_global_seed(args.seed)
    args.output.mkdir(parents=True, exist_ok=True)

    file_records, package_records = load_d2(args.data_dir)
    files_by_pkg = group_files(file_records)
    logger.info(
        "Loaded %d files across %d packages", len(file_records), len(package_records)
    )

    classifier = ClassifierAgent(
        checkpoint=args.checkpoint, batch_size=args.batch_size
    )
    if args.explain:
        from lamps.llms import GeminiClient

        verdict_llm = GeminiClient()
    else:
        verdict_llm = None
    verdict_agent = VerdictAgent(llm=verdict_llm)

    # ------------------------------------------------------------------
    # File-level classification (single batch over the entire corpus)
    # ------------------------------------------------------------------
    files: list[ExtractedFile] = [
        ExtractedFile(
            package=str(r["package"]),
            path=Path("<memory>"),
            rel_path=str(r["path"]),
            source=str(r["func"]),
        )
        for r in file_records
    ]
    logger.info("Classifying %d files with batch size %d", len(files), args.batch_size)
    classifications = classifier.classify_files(files)

    # ------------------------------------------------------------------
    # File-level metrics (used to mirror Table 3 / Fig. 7 in the paper)
    # ------------------------------------------------------------------
    y_file_true = [int(r["target"]) for r in file_records]
    y_file_pred = [c.target for c in classifications]
    file_report = classification_report(y_file_true, y_file_pred)
    logger.info("\nLAMPS on D2 (file-level)\n%s", format_report(file_report))

    # ------------------------------------------------------------------
    # Package-level aggregation
    # ------------------------------------------------------------------
    cls_by_pkg: dict[str, list[FileClassification]] = defaultdict(list)
    for cls in classifications:
        cls_by_pkg[cls.package].append(cls)

    package_predictions: list[dict] = []
    y_pkg_true: list[int] = []
    y_pkg_pred: list[int] = []
    for pkg in package_records:
        name = pkg["package"]
        true_label = int(pkg["label"])
        verdict = verdict_agent.aggregate(
            package=name, predictions=cls_by_pkg.get(name, [])
        )
        y_pkg_true.append(true_label)
        y_pkg_pred.append(verdict.target)
        package_predictions.append(
            {
                "package": name,
                "target": true_label,
                "predicted": verdict.target,
                "label": verdict.label,
                "n_files": verdict.n_files,
                "n_malicious_files": len(verdict.malicious_files),
                "rationale": verdict.rationale,
            }
        )

    package_report = classification_report(y_pkg_true, y_pkg_pred)
    logger.info("\nLAMPS on D2 (package-level)\n%s", format_report(package_report))

    # ------------------------------------------------------------------
    # Persist artefacts
    # ------------------------------------------------------------------
    (args.output / "file_predictions.jsonl").write_text(
        "\n".join(
            json.dumps(
                {
                    "idx": r["idx"],
                    "package": r["package"],
                    "path": r["path"],
                    "target": int(r["target"]),
                    "predicted": c.target,
                    "label": c.label,
                    "score": c.score,
                },
                ensure_ascii=False,
            )
            for r, c in zip(file_records, classifications)
        )
        + "\n"
    )
    (args.output / "package_predictions.jsonl").write_text(
        "\n".join(json.dumps(p, ensure_ascii=False) for p in package_predictions)
        + "\n"
    )
    (args.output / "file_report.json").write_text(json.dumps(file_report.to_dict(), indent=2))
    (args.output / "package_report.json").write_text(
        json.dumps(package_report.to_dict(), indent=2)
    )
    (args.output / "package_report.txt").write_text(format_report(package_report))
    logger.info("Saved D2 artefacts to %s", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
