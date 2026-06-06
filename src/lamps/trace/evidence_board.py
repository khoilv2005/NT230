"""Shared Evidence Board for TRACE-LAMPS.

The board is the persistent structured state described in the paper. Agents do
not pass opaque strings to each other; they write auditable evidence here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from lamps.agents.classifier import FileClassification
from lamps.agents.extractor import ExtractedFile
from lamps.agents.fetcher import FetchResult
from lamps.agents.verdict import PackageVerdict


@dataclass
class EvidenceBoard:
    package: str
    requested_version: str | None = None
    resolved_version: str | None = None
    plan: dict[str, Any] = field(default_factory=dict)
    fetch: dict[str, Any] = field(default_factory=dict)
    files: dict[str, dict[str, Any]] = field(default_factory=dict)
    context: dict[str, dict[str, Any]] = field(default_factory=dict)
    classifications: dict[str, dict[str, Any]] = field(default_factory=dict)
    risks: dict[str, dict[str, Any]] = field(default_factory=dict)
    verifier: dict[str, Any] = field(default_factory=dict)
    verdict: dict[str, Any] = field(default_factory=dict)
    trace: list[dict[str, Any]] = field(default_factory=list)

    def event(self, agent: str, action: str, payload: dict[str, Any] | None = None) -> None:
        self.trace.append({"agent": agent, "action": action, "payload": payload or {}})

    def write_plan(self, plan: dict[str, Any]) -> None:
        self.plan = plan
        self.event("Supervisor / Planner Agent", "write_plan", plan)

    def write_fetch(self, fetch: FetchResult | None, archive_path: Path | None = None) -> None:
        if fetch is not None:
            self.resolved_version = fetch.version
            self.fetch = {
                "package": fetch.package,
                "version": fetch.version,
                "archive_path": str(fetch.archive_path),
                "archive_url": fetch.archive_url,
            }
        elif archive_path is not None:
            self.fetch = {"archive_path": str(archive_path)}
        self.event("Package Acquisition Agent", "write_fetch", self.fetch)

    def write_files(self, files: list[ExtractedFile]) -> None:
        self.files = {
            f.rel_path: {
                "package": f.package,
                "path": str(f.path),
                "rel_path": f.rel_path,
                "n_chars": len(f.source),
            }
            for f in files
        }
        self.event(
            "Package Acquisition Agent",
            "write_files",
            {"n_files": len(files), "paths": list(self.files)[:20]},
        )

    def write_context(self, context: dict[str, dict[str, Any]]) -> None:
        self.context = context
        self.event("Static Context Graph Agent", "write_context", {"n_files": len(context)})

    def write_classifications(self, classifications: list[FileClassification]) -> None:
        self.classifications = {
            c.rel_path: {
                "package": c.package,
                "path": c.rel_path,
                "label": c.label,
                "target": c.target,
                "score": c.score,
            }
            for c in classifications
        }
        self.event(
            "Semantic Classifier Agent",
            "write_codebert_scores",
            {"n_files": len(classifications)},
        )

    def write_risks(self, risk_rows: list[dict[str, Any]]) -> None:
        self.risks = {str(row["path"]): row for row in risk_rows}
        self.event("Risk-Calibrated Aggregator Agent", "write_risks", {"n_files": len(risk_rows)})

    def write_verifier(self, verifier: dict[str, Any]) -> None:
        self.verifier = verifier
        self.event("Critic / Verifier Agent", "write_verification", verifier)

    def write_verdict(self, verdict: PackageVerdict, explanation: str | None = None) -> None:
        self.verdict = verdict.to_dict()
        if explanation is not None:
            self.verdict["explanation"] = explanation
        self.event("Decision & Audit Agent", "write_verdict", self.verdict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "requested_version": self.requested_version,
            "resolved_version": self.resolved_version,
            "plan": self.plan,
            "fetch": self.fetch,
            "files": self.files,
            "context": self.context,
            "classifications": self.classifications,
            "risks": self.risks,
            "verifier": self.verifier,
            "verdict": self.verdict,
            "trace": self.trace,
        }
