"""Supervisor / Planner Agent for TRACE-LAMPS."""

from __future__ import annotations

import json
import re
from typing import Any


class SupervisorPlannerAgent:
    """Create an auditable analysis plan before package processing starts."""

    def __init__(self, llm: object | None = None) -> None:
        self.llm = llm

    def plan(
        self,
        package: str,
        version: str | None = None,
        mode: str = "live",
        n_files_hint: int | None = None,
    ) -> dict[str, Any]:
        prompt = (
            "You are the Supervisor / Planner Agent in TRACE-LAMPS. "
            "Return only JSON. Decide static analysis depth for a PyPI malware "
            "screening run. Do not request dynamic execution.\n\n"
            f"package={package}\nversion={version or 'latest'}\n"
            f"mode={mode}\nn_files_hint={n_files_hint}"
        )
        if self.llm is not None:
            parsed = self._try_llm_plan(prompt)
            if parsed:
                parsed.setdefault("package", package)
                parsed.setdefault("version", version)
                parsed.setdefault("static_only", True)
                return parsed

        return {
            "package": package,
            "version": version,
            "mode": mode,
            "analysis_depth": "standard",
            "static_only": True,
            "use_context_graph": True,
            "use_codebert": True,
            "use_rcpaa": True,
            "use_verifier": True,
            "reason": "default TRACE-LAMPS static plan",
        }

    def _try_llm_plan(self, prompt: str) -> dict[str, Any] | None:
        try:
            raw = self._call_llm(prompt)
            match = re.search(r"\{.*\}", raw, re.DOTALL)
            if not match:
                return None
            value = json.loads(match.group(0))
            return value if isinstance(value, dict) else None
        except Exception:
            return None

    def _call_llm(self, prompt: str) -> str:
        if hasattr(self.llm, "generate"):
            return self.llm.generate(prompt).text
        if callable(self.llm):
            return self.llm(prompt)
        if hasattr(self.llm, "run"):
            return self.llm.run(prompt)
        raise TypeError("Unsupported LLM interface")
