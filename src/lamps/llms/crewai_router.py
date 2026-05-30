"""Deterministic CrewAI tool router for the LAMPS paper pipeline.

CrewAI normally asks an LLM to decide which tool to call. Ollama Cloud models
can return empty responses through LiteLLM in that ReAct/tool-calling layer.
This router keeps CrewAI orchestration active while making tool selection
auditable and deterministic: each paper agent has exactly one tool, so the
router emits the required CrewAI action syntax for that tool.
"""

from __future__ import annotations

import json
import re
from typing import Any


def _messages_text(messages: str | list[dict[str, Any]]) -> str:
    if isinstance(messages, str):
        return messages
    return "\n".join(str(m.get("content", "")) for m in messages)


def _last_observation(text: str) -> str | None:
    marker = "Observation:"
    if marker not in text:
        return None
    tail = text.rsplit(marker, 1)[-1].strip()
    if tail.startswith("the result of the action") or "Once all necessary information" in tail:
        return None
    if "Thought:" in tail:
        tail = tail.split("Thought:", 1)[0].strip()
    return tail or None


def _extract_package(text: str) -> str:
    patterns = [
        r"For package '([^']+)'",
        r'"package"\s*:\s*"([^"]+)"',
        r"'package'\s*:\s*'([^']+)'",
    ]
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1)
    return ""


def _extract_version(text: str) -> str | None:
    patterns = [
        r"optional version '([^']*)'",
        r'"version"\s*:\s*"([^"]*)"',
        r"'version'\s*:\s*'([^']*)'",
    ]
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1) or None
    return None


class CrewAIToolRouterLLM:  # subclassed lazily to avoid mandatory CrewAI import
    """Return CrewAI ReAct actions for the four fixed LAMPS tools."""

    def __new__(cls):
        from crewai import BaseLLM

        class _Router(BaseLLM):
            def __init__(self) -> None:
                super().__init__(model="lamps-crewai-tool-router")

            def call(
                self,
                messages: str | list[dict[str, Any]],
                tools: list[dict[str, Any]] | None = None,
                callbacks: list[Any] | None = None,
                available_functions: dict[str, Any] | None = None,
                from_task: Any | None = None,
                from_agent: Any | None = None,
                response_model: type[Any] | None = None,
            ) -> str:
                text = _messages_text(messages)
                observation = _last_observation(text)
                if observation is not None:
                    return f"Final Answer: {observation}"

                package = _extract_package(text)
                version = _extract_version(text)
                agent_role = getattr(from_agent, "role", "") if from_agent else ""
                task_text = getattr(from_task, "description", "") if from_task else ""
                route_text = f"{agent_role}\n{task_text}\n{text}"

                if "fetch_pypi_source_archive" in route_text:
                    action_input = {"package": package, "version": version}
                    return (
                        "Thought: I need to fetch the requested PyPI source archive.\n"
                        "Action: fetch_pypi_source_archive\n"
                        f"Action Input: {json.dumps(action_input)}"
                    )
                if "extract_relevant_python_files" in route_text:
                    action_input = {"package": package, "archive_path": None}
                    return (
                        "Thought: I need to extract and select relevant Python files.\n"
                        "Action: extract_relevant_python_files\n"
                        f"Action Input: {json.dumps(action_input)}"
                    )
                if "classify_python_files" in route_text:
                    action_input = {"package": package}
                    return (
                        "Thought: I need to classify selected Python files.\n"
                        "Action: classify_python_files\n"
                        f"Action Input: {json.dumps(action_input)}"
                    )
                if "aggregate_package_verdict" in route_text:
                    action_input = {"package": package}
                    return (
                        "Thought: I need to aggregate file predictions into a package verdict.\n"
                        "Action: aggregate_package_verdict\n"
                        f"Action Input: {json.dumps(action_input)}"
                    )
                return "Final Answer: No LAMPS tool route matched."

        return _Router()
