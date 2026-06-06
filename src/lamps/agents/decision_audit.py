"""Decision & Audit Agent for TRACE-LAMPS."""

from __future__ import annotations

import json
from typing import Any

from lamps.agents.verdict import PackageVerdict
from lamps.trace.evidence_board import EvidenceBoard


class DecisionAuditAgent:
    """Emit final structured verdict and optional LLM rationale."""

    def __init__(self, llm: object | None = None) -> None:
        self.llm = llm

    def decide(self, board: EvidenceBoard, verdict: PackageVerdict) -> dict[str, Any]:
        structured = self._structured_record(board, verdict)
        explanation = self._explain(structured) if self.llm is not None else self._fallback_explanation(structured)
        structured["explanation"] = explanation
        verdict.rationale = explanation
        verdict.structured_outcome = structured
        verdict.confidence = float(structured["confidence"])
        verdict.trigger_file = str(structured["trigger_file"])
        verdict.reason = str(structured["reason"])
        return structured

    def _structured_record(
        self, board: EvidenceBoard, verdict: PackageVerdict
    ) -> dict[str, Any]:
        risks = list(board.risks.values())
        top = sorted(risks, key=lambda row: float(row.get("calibrated_score", 0.0)), reverse=True)
        trigger = top[0] if top else {}
        trigger_file = str(trigger.get("path", ""))
        context = board.context.get(trigger_file, {})
        contributing = self._contributing_indicators(trigger, context)
        penalties = self._benign_penalties(trigger, context)
        reason = verdict.reason or self._reason(verdict, trigger, contributing, penalties)
        return {
            "package": board.package,
            "requested_version": board.requested_version,
            "resolved_version": board.resolved_version,
            "verdict": verdict.label,
            "label": verdict.label,
            "target": verdict.target,
            "confidence": float(trigger.get("calibrated_score", verdict.confidence or 0.0)),
            "threshold": float(trigger.get("threshold", 0.72)),
            "trigger_file": trigger_file,
            "reason": reason,
            "contributing_indicators": contributing,
            "benign_penalties": penalties,
            "verifier": board.verifier,
            "top_risk_files": top[:5],
        }

    def _contributing_indicators(
        self, risk: dict[str, Any], context: dict[str, Any]
    ) -> list[str]:
        indicators = []
        if risk.get("is_critical"):
            indicators.append("critical_file_role")
        if risk.get("imported_by_critical") or context.get("imported_by_entrypoint"):
            indicators.append("entrypoint_import_relation")
        indicators.extend(context.get("suspicious_indicators", []))
        reasons = risk.get("reasons", "")
        if isinstance(reasons, str):
            indicators.extend(part.strip() for part in reasons.split(";") if part.strip())
        elif isinstance(reasons, list):
            indicators.extend(str(part) for part in reasons)
        return sorted(set(indicators))

    def _benign_penalties(
        self, risk: dict[str, Any], context: dict[str, Any]
    ) -> list[str]:
        penalties = list(context.get("benign_indicators", []))
        context_penalty = float(risk.get("context_penalty", 0.0))
        low_confidence_penalty = float(risk.get("low_confidence_penalty", 0.0))
        if context_penalty:
            penalties.append(f"context_penalty={context_penalty:.2f}")
        if low_confidence_penalty:
            penalties.append(f"low_confidence_penalty={low_confidence_penalty:.2f}")
        return sorted(set(penalties))

    def _reason(
        self,
        verdict: PackageVerdict,
        trigger: dict[str, Any],
        contributing: list[str],
        penalties: list[str],
    ) -> str:
        if verdict.target == 0:
            return "No file exceeded the RC-PAA risk threshold after context calibration."
        bits = contributing[:4] or ["high calibrated CodeBERT risk"]
        if penalties:
            bits.append(f"penalties considered: {', '.join(penalties[:3])}")
        path = trigger.get("path", "")
        return f"Trigger file {path} exceeded RC-PAA threshold with evidence: {', '.join(bits)}."

    def _fallback_explanation(self, record: dict[str, Any]) -> str:
        return (
            f"Package '{record['package']}' is {record['verdict']} by TRACE-LAMPS. "
            f"Trigger file: {record['trigger_file'] or 'none'}; "
            f"confidence={record['confidence']:.4f}; reason: {record['reason']}"
        )

    def _explain(self, record: dict[str, Any]) -> str:
        prompt = (
            "You are the Decision & Audit Agent in TRACE-LAMPS. "
            "Write a concise 3-5 sentence natural-language explanation from "
            "the JSON evidence. Do not invent evidence. Do not change verdict, "
            "confidence, trigger file, or threshold.\n\n"
            f"{json.dumps(record, indent=2)}"
        )
        try:
            if hasattr(self.llm, "generate"):
                text = self.llm.generate(prompt).text
            elif callable(self.llm):
                text = self.llm(prompt)
            elif hasattr(self.llm, "run"):
                text = self.llm.run(prompt)
            else:
                text = ""
            return text.strip() or self._fallback_explanation(record)
        except Exception as exc:
            return f"{self._fallback_explanation(record)} LLM audit note unavailable: {exc}"
