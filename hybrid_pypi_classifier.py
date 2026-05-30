"""LAMPS demo CLI — analyse a single PyPI package end-to-end.

Reproduces the live-mode example from the paper: given a package name,
the four LAMPS agents collaborate to fetch the source archive, extract
its Python files, classify each file with the fine-tuned CodeBERT
model, and aggregate the results into a package-level verdict.

Example::

    python hybrid_pypi_classifier.py --package requests
    python hybrid_pypi_classifier.py --package requests --version 2.31.0
    python hybrid_pypi_classifier.py --package requests --crewai --json --crew-json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow running as a script without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from lamps.config import CODEBERT_BEST_CKPT
from lamps.llms.ollama_client import DEFAULT_MODEL as OLLAMA_DEFAULT_MODEL
from lamps.llms.ollama_client import OLLAMA_CLOUD_HOST
from lamps.utils import configure_logging, logger


def build_ollama_cloud(model: str, host: str = OLLAMA_CLOUD_HOST):
    """Create the Ollama Cloud client used by LAMPS reasoning agents."""
    from lamps.llms.ollama_client import OllamaClient

    return OllamaClient(model=model, host=host)


def build_pipeline(
    checkpoint: Path,
    explain: bool,
    use_crewai: bool = False,
    ollama_model: str = OLLAMA_DEFAULT_MODEL,
    ollama_host: str = OLLAMA_CLOUD_HOST,
):
    """Wire up the four agents into a runnable pipeline."""
    from lamps.agents.classifier import ClassifierAgent
    from lamps.agents.extractor import ExtractorAgent, LLMArchiveExtractorAgent
    from lamps.agents.fetcher import FetcherAgent
    from lamps.agents.verdict import VerdictAgent
    from lamps.crewai_pipeline import LampsCrewPipeline
    from lamps.llms.crewai_router import CrewAIToolRouterLLM
    from lamps.pipeline import LampsPipeline

    fetcher = FetcherAgent()
    classifier = ClassifierAgent(checkpoint=checkpoint)

    if use_crewai:
        llm = build_ollama_cloud(model=ollama_model, host=ollama_host)
        extractor = LLMArchiveExtractorAgent(llm=llm)
        verdict = VerdictAgent(llm=llm)
    elif explain:
        llm = build_ollama_cloud(model=ollama_model, host=ollama_host)
        extractor = ExtractorAgent()
        verdict = VerdictAgent(llm=llm)
    else:
        extractor = ExtractorAgent()
        verdict = VerdictAgent(llm=None)

    pipeline_cls = LampsCrewPipeline if use_crewai else LampsPipeline
    pipeline_kwargs = {
        "fetcher": fetcher,
        "extractor": extractor,
        "classifier": classifier,
        "verdict": verdict,
    }
    if use_crewai:
        pipeline_kwargs["crew_llm"] = CrewAIToolRouterLLM()
    pipeline = pipeline_cls(**pipeline_kwargs)
    if use_crewai:
        pipeline.crew = pipeline.build_crew()
    return pipeline


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
        help="Use Ollama Cloud for Verdict Agent rationale (requires OLLAMA_API_KEY).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the verdict as a JSON object instead of human-readable text.",
    )
    parser.add_argument(
        "--crewai",
        action="store_true",
        help="Use the CrewAI-backed full pipeline with Ollama Cloud Extractor/Verdict.",
    )
    parser.add_argument(
        "--crew-json",
        action="store_true",
        help="Include the CrewAI-style execution trace in JSON output.",
    )
    parser.add_argument(
        "--ollama-model",
        default=OLLAMA_DEFAULT_MODEL,
        help="Ollama model for reasoning agents.",
    )
    parser.add_argument(
        "--ollama-host",
        default=OLLAMA_CLOUD_HOST,
        help="Ollama host. Default is Ollama Cloud.",
    )
    args = parser.parse_args()

    configure_logging()

    pipeline = build_pipeline(
        args.checkpoint,
        explain=args.explain,
        use_crewai=args.crewai,
        ollama_model=args.ollama_model,
        ollama_host=args.ollama_host,
    )
    logger.info("Analysing package %s%s", args.package, f"=={args.version}" if args.version else "")
    result = pipeline.analyze_package(args.package, version=args.version)

    if args.json:
        payload = result.to_dict()
        if args.crew_json and getattr(pipeline, "last_execution", None) is not None:
            payload["crew_execution"] = pipeline.last_execution.to_dict()
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(render_human(result))
        if args.crewai and getattr(pipeline, "last_execution", None) is not None:
            print("\nCrewAI execution trace:")
            for step in pipeline.last_execution.steps:
                print(f"  - {step.agent}: {step.action}")

    # Exit code: 0 = analysis succeeded (regardless of verdict).
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
