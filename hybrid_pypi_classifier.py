"""LAMPS demo CLI — analyse a single PyPI package end-to-end.

Reproduces the live-mode example from the paper: given a package name,
the four LAMPS agents collaborate to fetch the source archive, extract
its Python files, classify each file with the fine-tuned CodeBERT
model, and aggregate the results into a package-level verdict.

Example::

    python hybrid_pypi_classifier.py --package requests
    python hybrid_pypi_classifier.py --package requests --version 2.31.0
    python hybrid_pypi_classifier.py --package requests --explain --json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow running as a script without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from lamps.agents.classifier import ClassifierAgent
from lamps.agents.extractor import ExtractorAgent
from lamps.agents.fetcher import FetcherAgent
from lamps.agents.verdict import VerdictAgent
from lamps.config import CODEBERT_BEST_CKPT
from lamps.pipeline import LampsPipeline
from lamps.utils import configure_logging, logger


def build_pipeline(checkpoint: Path, explain: bool) -> LampsPipeline:
    """Wire up the four agents into a runnable pipeline."""
    fetcher = FetcherAgent()
    extractor = ExtractorAgent()
    classifier = ClassifierAgent(checkpoint=checkpoint)

    if explain:
        from lamps.llms import GeminiClient

        verdict = VerdictAgent(llm=GeminiClient())
    else:
        verdict = VerdictAgent(llm=None)

    return LampsPipeline(
        fetcher=fetcher,
        extractor=extractor,
        classifier=classifier,
        verdict=verdict,
    )


def render_human(result) -> str:
    verdict = result.verdict
    lines = [
        f"\n=== LAMPS verdict for {verdict.package} ===",
        f"  Decision   : {verdict.label.upper()}",
        f"  Files seen : {verdict.n_files}",
        f"  Malicious  : {len(verdict.malicious_files)}",
    ]
    if verdict.malicious_files:
        lines.append("  Flagged files:")
        for f in verdict.malicious_files[:10]:
            lines.append(f"    - {f.rel_path}  (score={f.score:.3f})")
    if verdict.rationale:
        lines.append("\nRationale:")
        lines.append("  " + verdict.rationale.replace("\n", "\n  "))
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True, help="PyPI package name (e.g. requests)")
    parser.add_argument("--version", default=None, help="Optional specific version")
    parser.add_argument(
        "--checkpoint",
        type=Path,
        default=CODEBERT_BEST_CKPT,
        help="Path to the fine-tuned CodeBERT checkpoint (model.bin).",
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        help="Use the Gemini-backed Verdict Agent to generate a natural-language "
        "rationale (requires GEMINI_API_KEY).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the verdict as a JSON object instead of human-readable text.",
    )
    args = parser.parse_args()

    configure_logging()

    pipeline = build_pipeline(args.checkpoint, explain=args.explain)
    logger.info("Analysing package %s%s", args.package, f"=={args.version}" if args.version else "")
    result = pipeline.analyze_package(args.package, version=args.version)

    if args.json:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(render_human(result))

    # Exit code: 0 = analysis succeeded (regardless of verdict).
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
