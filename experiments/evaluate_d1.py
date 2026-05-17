"""Evaluate LAMPS on D1 (paper §5.1).

D1 is the balanced collection of 6000 setup.py files (3000 malicious,
3000 benign). Each file belongs to a single package, so the file-level
prediction from the Classifier Agent equals the package-level verdict
produced by the Verdict Agent (the conservative aggregation rule has no
effect on a 1-file package).

Pipeline
--------
1. Load ``data/d1/test.jsonl`` produced by ``prepare_d1.py``.
2. Run the fine-tuned CodeBERT classifier (Classifier Agent) over every
   setup.py in the test split.
3. Run the Verdict Agent's conservative aggregator on each (single-file)
   package to obtain a package-level label.
4. Report Accuracy / Precision / Recall / F1 / Balanced Accuracy.
5. Persist predictions and metrics to ``results/d1/``.

Run::

    python -m experiments.evaluate_d1 --output results/d1
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from lamps.agents.classifier import ClassifierAgent
from lamps.agents.extractor import ExtractedFile
from lamps.agents.verdict import VerdictAgent
from lamps.config import CODEBERT_BEST_CKPT, D1_PREPARED_DIR, RESULTS_DIR
from lamps.evaluation.metrics import classification_report, format_report
from lamps.utils import configure_logging, logger, read_jsonl, set_global_seed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=D1_PREPARED_DIR)
    parser.add_argument("--checkpoint", type=Path, default=CODEBERT_BEST_CKPT)
    parser.add_argument("--output", type=Path, default=RESULTS_DIR / "d1")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument(
        "--explain",
        action="store_true",
        help="Use the Gemini-backed Verdict Agent to generate rationales "
        "(slow; requires GEMINI_API_KEY). Defaults to deterministic rationales.",
    )
    args = parser.parse_args()

    configure_logging()
    set_global_seed(args.seed)
    args.output.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Build the agents
    # ------------------------------------------------------------------
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
    # Load D1 test split as one ExtractedFile per record
    # ------------------------------------------------------------------
    test_path = args.data_dir / "test.jsonl"
    if not test_path.exists():
        raise FileNotFoundError(
            f"Missing {test_path}. Run `python -m lamps.data.prepare_d1` first."
        )

    records = list(read_jsonl(test_path))
    logger.info("Loaded %d test records from %s", len(records), test_path)

    files: list[ExtractedFile] = [
        ExtractedFile(
            package=str(r["package"]),
            path=Path("<memory>"),
            rel_path="setup.py",
            source=str(r["func"]),
        )
        for r in records
    ]
    y_true = [int(r["target"]) for r in records]

    # ------------------------------------------------------------------
    # Classifier Agent: per-file predictions
    # ------------------------------------------------------------------
    logger.info("Classifying %d setup.py files...", len(files))
    classifications = classifier.classify_files(files)

    # ------------------------------------------------------------------
    # Verdict Agent: package-level aggregation (1 file per package on D1)
    # ------------------------------------------------------------------
    package_predictions: list[dict] = []
    y_pred: list[int] = []
    for record, classification in zip(records, classifications):
        verdict = verdict_agent.aggregate(
            package=str(record["package"]), predictions=[classification]
        )
        y_pred.append(verdict.target)
        package_predictions.append(
            {
                "idx": record["idx"],
                "package": record["package"],
                "version": record.get("version"),
                "target": int(record["target"]),
                "predicted": verdict.target,
                "label": verdict.label,
                "score": classification.score,
                "rationale": verdict.rationale,
            }
        )

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------
    report = classification_report(y_true, y_pred)
    logger.info("\nLAMPS on D1\n%s", format_report(report))

    (args.output / "predictions.jsonl").write_text(
        "\n".join(json.dumps(p, ensure_ascii=False) for p in package_predictions)
        + "\n"
    )
    (args.output / "report.json").write_text(json.dumps(report.to_dict(), indent=2))
    (args.output / "report.txt").write_text(format_report(report))
    logger.info("Saved D1 artefacts to %s", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
