"""TRACE-LAMPS full pipeline.

Paper flow:
Supervisor/Planner -> Package Acquisition -> Static Context Graph ->
Semantic Classifier(CodeBERT) -> RC-PAA -> Critic/Verifier -> Decision/Audit.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from lamps.agents.classifier import ClassifierAgent, FileClassification
from lamps.agents.context_graph import StaticContextGraphAgent
from lamps.agents.critic_verifier import CriticVerifierAgent
from lamps.agents.decision_audit import DecisionAuditAgent
from lamps.agents.extractor import ExtractedFile
from lamps.agents.fetcher import FetchResult
from lamps.agents.package_acquisition import PackageAcquisitionAgent
from lamps.agents.planner import SupervisorPlannerAgent
from lamps.agents.risk_calibrated_verdict import RiskCalibratedVerdictAgent
from lamps.agents.verdict import PackageVerdict
from lamps.llms.ollama_client import OllamaClient
from lamps.trace.evidence_board import EvidenceBoard


@dataclass
class TraceLampsResult:
    package: str
    verdict: PackageVerdict
    board: EvidenceBoard
    fetch: FetchResult | None = None
    files: list[ExtractedFile] | None = None
    classifications: list[FileClassification] | None = None

    def to_dict(self) -> dict:
        return {
            "package": self.package,
            "verdict": self.verdict.to_dict(),
            "fetch": (
                {
                    "version": self.fetch.version,
                    "archive_url": self.fetch.archive_url,
                    "archive_path": str(self.fetch.archive_path),
                }
                if self.fetch is not None
                else None
            ),
            "files": [
                {
                    "path": f.rel_path,
                    "n_chars": len(f.source),
                }
                for f in (self.files or [])
            ],
            "classifications": [
                {
                    "path": c.rel_path,
                    "label": c.label,
                    "target": c.target,
                    "score": c.score,
                }
                for c in (self.classifications or [])
            ],
            "evidence_board": self.board.to_dict(),
        }


class TraceLampsPipeline:
    """High-level TRACE-LAMPS controller matching the current paper method."""

    def __init__(
        self,
        planner: SupervisorPlannerAgent | None = None,
        acquisition: PackageAcquisitionAgent | None = None,
        context_graph: StaticContextGraphAgent | None = None,
        classifier: ClassifierAgent | None = None,
        aggregator: RiskCalibratedVerdictAgent | None = None,
        verifier: CriticVerifierAgent | None = None,
        audit: DecisionAuditAgent | None = None,
        llm: object | None = None,
        use_ollama: bool = True,
        ollama_model: str | None = None,
        package_threshold: float = 0.72,
    ) -> None:
        reasoning_llm = llm if llm is not None else self._default_llm(use_ollama, ollama_model)
        self.planner = planner or SupervisorPlannerAgent(llm=reasoning_llm)
        self.acquisition = acquisition or PackageAcquisitionAgent()
        self.context_graph = context_graph or StaticContextGraphAgent()
        self.classifier = classifier or ClassifierAgent()
        self.aggregator = aggregator or RiskCalibratedVerdictAgent(
            llm=None,
            package_threshold=package_threshold,
        )
        self.verifier = verifier or CriticVerifierAgent(
            llm=reasoning_llm,
            threshold=package_threshold,
        )
        self.audit = audit or DecisionAuditAgent(llm=reasoning_llm)

    def analyze_package(
        self, package: str, version: str | None = None
    ) -> TraceLampsResult:
        board = EvidenceBoard(package=package, requested_version=version)
        plan = self.planner.plan(package=package, version=version, mode="live")
        board.write_plan(plan)

        fetch, files = self.acquisition.acquire(package, version=version)
        board.write_fetch(fetch)
        board.write_files(files)
        return self._finish(package, board, files, fetch=fetch)

    def analyze_local_archive(
        self, archive_path: Path, package: str, version: str | None = None
    ) -> TraceLampsResult:
        board = EvidenceBoard(package=package, requested_version=version)
        plan = self.planner.plan(package=package, version=version, mode="local_archive")
        board.write_plan(plan)
        board.write_fetch(None, archive_path=Path(archive_path))

        files = self.acquisition.extract(Path(archive_path), package)
        board.write_files(files)
        return self._finish(package, board, files, fetch=None)

    def analyze_files(
        self,
        package: str,
        files: Iterable[ExtractedFile],
        version: str | None = None,
    ) -> TraceLampsResult:
        files_list = list(files)
        board = EvidenceBoard(package=package, requested_version=version)
        plan = self.planner.plan(
            package=package,
            version=version,
            mode="pre_extracted_files",
            n_files_hint=len(files_list),
        )
        board.write_plan(plan)
        board.write_files(files_list)
        return self._finish(package, board, files_list, fetch=None)

    def _finish(
        self,
        package: str,
        board: EvidenceBoard,
        files: list[ExtractedFile],
        fetch: FetchResult | None,
    ) -> TraceLampsResult:
        context = self.context_graph.analyze(files)
        board.write_context(context)

        classifications = self.classifier.classify_files(files)
        board.write_classifications(classifications)

        verdict = self.aggregator.aggregate(package, classifications, files)
        board.write_risks(self.aggregator.risk_rows())

        verification = self.verifier.verify(board)
        board.write_verifier(verification)

        audit_record = self.audit.decide(board, verdict)
        board.write_verdict(verdict, explanation=audit_record.get("explanation"))

        return TraceLampsResult(
            package=package,
            verdict=verdict,
            board=board,
            fetch=fetch,
            files=files,
            classifications=classifications,
        )

    def _default_llm(self, use_ollama: bool, model: str | None) -> object | None:
        if not use_ollama:
            return None
        return OllamaClient(
            model=model or os.getenv("OLLAMA_MODEL", "deepseek-v4-flash:cloud")
        )
