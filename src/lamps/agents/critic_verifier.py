"""Critic / Verifier Agent for TRACE-LAMPS."""

from __future__ import annotations

import json
from typing import Any

from lamps.trace.evidence_board import EvidenceBoard


class CriticVerifierAgent:
    """Inspect conflicts between classifier scores, context, and RC-PAA risk."""

    def __init__(
        self,
        llm: object | None = None,
        threshold: float = 0.72,
        near_threshold_margin: float = 0.05,
    ) -> None:
        self.llm = llm
        self.threshold = threshold
        self.near_threshold_margin = near_threshold_margin

    def verify(self, board: EvidenceBoard) -> dict[str, Any]:
        risks = list(board.risks.values())
        top = max(risks, key=lambda row: float(row.get("calibrated_score", 0.0)), default=None)
        package_risk = float(top.get("calibrated_score", 0.0)) if top else 0.0
        triggers = []
        conflicts = []

        if top:
            path = str(top.get("path", ""))
            context = board.context.get(path, {})
            cls = board.classifications.get(path, {})
            benign_indicators = context.get("benign_indicators", [])
            suspicious = context.get("suspicious_indicators", [])
            base_score = float(top.get("base_score", cls.get("score", 0.0)))

            if package_risk >= self.threshold and benign_indicators:
                triggers.append("high_risk_in_benign_context_path")
                conflicts.append(
                    {
                        "path": path,
                        "type": "benign_context_high_risk",
                        "benign_indicators": benign_indicators,
                        "risk": package_risk,
                    }
                )
            if context.get("is_generated_or_resource") and package_risk >= self.threshold:
                triggers.append("generated_resource_drives_package_risk")
            if base_score < 0.5 and suspicious:
                triggers.append("classifier_context_conflict")
                conflicts.append(
                    {
                        "path": path,
                        "type": "low_classifier_score_with_static_indicators",
                        "base_score": base_score,
                        "suspicious_indicators": suspicious,
                    }
                )
            if base_score < 0.72 and context.get("is_critical") and suspicious:
                triggers.append("low_confidence_strong_installer_evidence")

        if abs(package_risk - self.threshold) <= self.near_threshold_margin:
            triggers.append("near_threshold_package_risk")

        result = {
            "needs_review": bool(triggers),
            "threshold": self.threshold,
            "package_risk": package_risk,
            "trigger_file": str(top.get("path", "")) if top else "",
            "triggers": sorted(set(triggers)),
            "conflicts": conflicts,
            "recommendation": "manual_review" if triggers else "accept_rcpaa_verdict",
        }
        if self.llm is not None:
            result["llm_note"] = self._llm_note(result)
        return result

    def _llm_note(self, result: dict[str, Any]) -> str:
        prompt = (
            "You are the Critic / Verifier Agent in TRACE-LAMPS. "
            "Given this deterministic verification JSON, write one concise "
            "audit note. Do not change verdicts or scores.\n\n"
            f"{json.dumps(result, indent=2)}"
        )
        try:
            if hasattr(self.llm, "generate"):
                return self.llm.generate(prompt).text
            if callable(self.llm):
                return self.llm(prompt)
            if hasattr(self.llm, "run"):
                return self.llm.run(prompt)
        except Exception as exc:
            return f"LLM verifier note unavailable: {exc}"
        return ""
