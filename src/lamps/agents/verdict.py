"""Verdict Agent (paper §3.1, §3.2).

Aggregates per-file predictions into a package-level verdict using the
*conservative* policy described in the paper: if **any** file in the package
is classified as malicious, the package is flagged as malicious. The agent
also emits a short natural-language rationale via an LLM when one is
available.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional, Sequence

from lamps.agents.classifier import FileClassification


@dataclass
class PackageVerdict:
    package: str
    label: str                                  # "malicious" or "benign"
    target: int                                 # 1 or 0
    malicious_files: list[FileClassification] = field(default_factory=list)
    benign_files: list[FileClassification] = field(default_factory=list)
    rationale: str = ""

    @property
    def n_files(self) -> int:
        return len(self.malicious_files) + len(self.benign_files)

    def to_dict(self) -> dict:
        return {
            "package": self.package,
            "label": self.label,
            "target": self.target,
            "n_files": self.n_files,
            "malicious_files": [
                {"path": f.rel_path, "score": f.score} for f in self.malicious_files
            ],
            "rationale": self.rationale,
        }


class VerdictAgent:
    """Conservative package-level aggregator with optional LLM explanations."""

    def __init__(self, llm: Optional[object] = None) -> None:
        # ``llm`` must expose a ``generate(prompt) -> response`` or
        # ``run(prompt) -> str`` API. None disables explanations.
        self.llm = llm

    # ------------------------------------------------------------------
    def aggregate(
        self, package: str, predictions: Sequence[FileClassification]
    ) -> PackageVerdict:
        """Apply the conservative aggregation rule."""
        malicious = [p for p in predictions if p.target == 1]
        benign = [p for p in predictions if p.target == 0]
        if malicious:
            verdict = PackageVerdict(
                package=package,
                label="malicious",
                target=1,
                malicious_files=list(malicious),
                benign_files=list(benign),
            )
        else:
            verdict = PackageVerdict(
                package=package,
                label="benign",
                target=0,
                malicious_files=[],
                benign_files=list(benign),
            )

        if self.llm is not None:
            verdict.rationale = self._explain(verdict)
        else:
            verdict.rationale = self._fallback_rationale(verdict)
        return verdict

    # ------------------------------------------------------------------
    def _fallback_rationale(self, verdict: PackageVerdict) -> str:
        """Deterministic rationale used when no LLM is configured."""
        if verdict.target == 1:
            highlights = "; ".join(
                f"{f.rel_path} (score={f.score:.2f})"
                for f in verdict.malicious_files[:5]
            )
            return (
                f"Package '{verdict.package}' is flagged as MALICIOUS because "
                f"{len(verdict.malicious_files)} of its {verdict.n_files} files "
                f"were classified as malicious. Examples: {highlights}."
            )
        return (
            f"Package '{verdict.package}' is BENIGN: all {verdict.n_files} "
            "extracted files passed the file-level classifier."
        )

    # ------------------------------------------------------------------
    def _explain(self, verdict: PackageVerdict) -> str:
        """Use the configured LLM to produce a short rationale."""
        prompt = self._build_prompt(verdict)
        try:
            if hasattr(self.llm, "generate"):
                return self.llm.generate(prompt).text
            if callable(self.llm):
                return self.llm(prompt)
            if hasattr(self.llm, "run"):
                return self.llm.run(prompt)
        except Exception as exc:  # pragma: no cover - network failures
            return f"{self._fallback_rationale(verdict)} (LLM error: {exc})"
        return self._fallback_rationale(verdict)

    # ------------------------------------------------------------------
    def _build_prompt(self, verdict: PackageVerdict) -> str:
        """Compose the rationale prompt described in paper §3.2."""
        flagged = [
            {"path": f.rel_path, "score": round(f.score, 4)}
            for f in verdict.malicious_files[:10]
        ]
        payload = {
            "package": verdict.package,
            "verdict": verdict.label,
            "n_files": verdict.n_files,
            "n_malicious": len(verdict.malicious_files),
            "flagged_files": flagged,
        }
        return (
            "You are the Verdict Agent in the LAMPS pipeline. Apply a "
            "conservative aggregation policy: if any file is malicious, the "
            "entire package is malicious. Given the per-file classification "
            "results below, produce a concise (3-5 sentences) rationale that "
            "names the suspicious files and the behavioural patterns they "
            "suggest (e.g. base64-encoded payloads, hidden subprocess calls, "
            "outbound network connections, unauthorized I/O).\n\n"
            f"{json.dumps(payload, indent=2)}"
        )
