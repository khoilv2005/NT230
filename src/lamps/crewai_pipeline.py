"""CrewAI-backed orchestration for the four-agent LAMPS workflow.

The paper describes LAMPS as four role-specialised agents coordinated through
CrewAI. This module keeps the existing deterministic Python agents as the
auditable implementation of each role, while adding a CrewAI crew definition
and CrewAI tool adapters for the paper-level architecture:

Fetcher -> Extractor -> Classifier -> Verdict.

The default ``analyze_*`` methods execute those roles deterministically. Use
``build_crew()`` when an external script wants the actual CrewAI ``Crew``
object for inspection, UI integration, or LLM-driven experiments.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from lamps.agents.classifier import ClassifierAgent, FileClassification
    from lamps.agents.extractor import ExtractedFile, ExtractorAgent
    from lamps.agents.fetcher import FetcherAgent, FetchResult
    from lamps.agents.verdict import PackageVerdict, VerdictAgent


class CrewAINotInstalledError(ImportError):
    """Raised when CrewAI-specific objects are requested without CrewAI."""


@dataclass
class CrewAIStep:
    """Auditable trace for one LAMPS role execution."""

    agent: str
    action: str
    output: dict[str, Any]


@dataclass
class CrewAIExecution:
    """Trace attached to the latest CrewAI pipeline run."""

    package: str
    steps: list[CrewAIStep]

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "steps": [
                {"agent": s.agent, "action": s.action, "output": s.output}
                for s in self.steps
            ],
        }

@dataclass
class LampsCrewResult:
    """LAMPS result object returned by the CrewAI-backed pipeline."""

    package: str
    verdict: "PackageVerdict"
    fetch: Optional["FetchResult"] = None
    files: list["FileClassification"] = None  # type: ignore[assignment]

    def to_dict(self) -> dict[str, Any]:
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
                    "label": f.label,
                    "score": f.score,
                }
                for f in (self.files or [])
            ],
        }


def _import_crewai():
    try:
        from crewai import Agent, Crew, Process, Task
    except ImportError as exc:  # pragma: no cover - depends on optional extra
        raise CrewAINotInstalledError(
            "CrewAI is not installed. Run `pip install -r requirements.txt`."
        ) from exc
    return Agent, Crew, Process, Task


def _summarize_files(files: list["ExtractedFile"]) -> list[dict[str, Any]]:
    return [
        {"path": f.rel_path, "chars": len(f.source)}
        for f in files
    ]


class LampsCrewPipeline:
    """Paper-aligned LAMPS pipeline with CrewAI role/task definitions."""

    def __init__(
        self,
        fetcher: Optional["FetcherAgent"] = None,
        extractor: Optional["ExtractorAgent"] = None,
        classifier: Optional["ClassifierAgent"] = None,
        verdict: Optional["VerdictAgent"] = None,
        crew_llm: Optional[object] = None,
        verbose: bool = False,
    ) -> None:
        if fetcher is None:
            from lamps.agents.fetcher import FetcherAgent

            fetcher = FetcherAgent()
        if extractor is None:
            from lamps.agents.extractor import ExtractorAgent

            extractor = ExtractorAgent()
        if classifier is None:
            from lamps.agents.classifier import ClassifierAgent

            classifier = ClassifierAgent()
        if verdict is None:
            from lamps.agents.verdict import VerdictAgent

            verdict = VerdictAgent()

        self.fetcher = fetcher
        self.extractor = extractor
        self.classifier = classifier
        self.verdict = verdict
        self.crew_llm = crew_llm
        self.verbose = verbose
        self.crew: Optional[object] = None
        self.last_execution: Optional[CrewAIExecution] = None
        self._state: dict[str, Any] = {}

    # ------------------------------------------------------------------
    # CrewAI architecture
    # ------------------------------------------------------------------
    def build_crew(self):
        """Return a CrewAI ``Crew`` matching the paper's four-agent design."""
        Agent, Crew, Process, Task = _import_crewai()
        tools = self.build_tools()

        agent_kwargs: dict[str, Any] = {
            "verbose": self.verbose,
            "allow_delegation": False,
            "max_iter": 5,
        }
        if self.crew_llm is not None:
            agent_kwargs["llm"] = self.crew_llm
            agent_kwargs["function_calling_llm"] = self.crew_llm

        fetcher_agent = Agent(
            role="Fetcher Agent",
            goal="Resolve a PyPI package and retrieve its source archive.",
            backstory=(
                "You initiate LAMPS by resolving package metadata, selecting "
                "the requested or latest stable version, and downloading the "
                "source distribution through an auditable Python tool."
            ),
            tools=[tools["fetch"]],
            **agent_kwargs,
        )
        extractor_agent = Agent(
            role="Extractor Agent",
            goal="Extract the archive and select relevant Python files.",
            backstory=(
                "You unpack source distributions and keep executable Python "
                "files while excluding tests, documentation, examples, vendor "
                "code, and other noisy artifacts."
            ),
            tools=[tools["extract"]],
            **agent_kwargs,
        )
        classifier_agent = Agent(
            role="Classifier Agent",
            goal="Classify each selected Python file as benign or malicious.",
            backstory=(
                "You call the fine-tuned CodeBERT classifier and produce "
                "file-level labels and scores for downstream aggregation."
            ),
            tools=[tools["classify"]],
            **agent_kwargs,
        )
        verdict_agent = Agent(
            role="Verdict Agent",
            goal="Aggregate file-level predictions into a package verdict.",
            backstory=(
                "You apply the conservative LAMPS policy: if any file is "
                "malicious, the whole package is malicious. You also provide "
                "a concise rationale from the classifier evidence."
            ),
            tools=[tools["verdict"]],
            **agent_kwargs,
        )

        fetch_task = Task(
            description=(
                "For package '{package}' and optional version '{version}', "
                "you MUST call the fetch_pypi_source_archive tool exactly once. "
                "Do not infer package metadata from memory. Return the tool output as JSON."
            ),
            expected_output="JSON with package, version, archive_path, and archive_url.",
            agent=fetcher_agent,
            tools=[tools["fetch"]],
        )
        extract_task = Task(
            description=(
                "Using the fetched package archive from context, you MUST call "
                "the extract_relevant_python_files tool exactly once and return "
                "the selected Python file list."
            ),
            expected_output="JSON with package, n_files, and selected file paths.",
            agent=extractor_agent,
            context=[fetch_task],
            tools=[tools["extract"]],
        )
        classify_task = Task(
            description=(
                "You MUST call the classify_python_files tool exactly once for "
                "the selected files and return file-level labels and confidence scores."
            ),
            expected_output="JSON with package, n_files, and per-file predictions.",
            agent=classifier_agent,
            context=[extract_task],
            tools=[tools["classify"]],
        )
        verdict_task = Task(
            description=(
                "You MUST call the aggregate_package_verdict tool exactly once "
                "to aggregate file predictions and return the final package-level "
                "LAMPS verdict."
            ),
            expected_output=(
                "JSON with package, label, target, n_files, "
                "n_malicious_files, and rationale."
            ),
            agent=verdict_agent,
            context=[classify_task],
            tools=[tools["verdict"]],
        )

        return Crew(
            agents=[
                fetcher_agent,
                extractor_agent,
                classifier_agent,
                verdict_agent,
            ],
            tasks=[fetch_task, extract_task, classify_task, verdict_task],
            process=Process.sequential,
            verbose=self.verbose,
        )

    def build_tools(self) -> dict[str, object]:
        """Create CrewAI tools that call the existing LAMPS Python agents."""
        try:
            from crewai.tools import BaseTool
            from pydantic import BaseModel, Field, PrivateAttr
        except ImportError as exc:  # pragma: no cover - depends on optional extra
            raise CrewAINotInstalledError(
                "CrewAI tools require `crewai` and `pydantic`. "
                "Run `pip install -r requirements.txt`."
            ) from exc

        pipeline = self

        class FetchInput(BaseModel):
            package: str = Field(..., description="PyPI package name.")
            version: Optional[str] = Field(default=None, description="Optional package version.")

        class ExtractInput(BaseModel):
            package: str = Field(..., description="PyPI package name.")
            archive_path: Optional[str] = Field(
                default=None,
                description="Optional archive path. Defaults to the last fetched archive.",
            )

        class ClassifyInput(BaseModel):
            package: str = Field(..., description="PyPI package name.")

        class VerdictInput(BaseModel):
            package: str = Field(..., description="PyPI package name.")

        class FetchPackageTool(BaseTool):
            name: str = "fetch_pypi_source_archive"
            description: str = "Resolve PyPI metadata and download a source distribution."
            args_schema: type[BaseModel] = FetchInput
            _pipeline: LampsCrewPipeline = PrivateAttr()

            def __init__(self, pipeline: LampsCrewPipeline) -> None:
                super().__init__()
                self._pipeline = pipeline

            def _run(self, package: str, version: Optional[str] = None) -> str:
                result = self._pipeline.fetcher.fetch(package, version=version)
                self._pipeline._state["fetch"] = result
                return json.dumps(
                    {
                        "package": result.package,
                        "version": result.version,
                        "archive_path": str(result.archive_path),
                        "archive_url": result.archive_url,
                    }
                )

        class ExtractPythonFilesTool(BaseTool):
            name: str = "extract_relevant_python_files"
            description: str = "Extract an archive and keep relevant Python files for analysis."
            args_schema: type[BaseModel] = ExtractInput
            _pipeline: LampsCrewPipeline = PrivateAttr()

            def __init__(self, pipeline: LampsCrewPipeline) -> None:
                super().__init__()
                self._pipeline = pipeline

            def _run(self, package: str, archive_path: Optional[str] = None) -> str:
                if not package:
                    fetch = self._pipeline._state.get("fetch")
                    if fetch is not None:
                        package = fetch.package
                if archive_path is None:
                    fetch = self._pipeline._state.get("fetch")
                    if fetch is None:
                        raise RuntimeError("No fetched archive in CrewAI state.")
                    archive = fetch.archive_path
                else:
                    archive = Path(archive_path)
                files = self._pipeline.extractor.extract(archive, package)
                self._pipeline._state["files"] = files
                return json.dumps(
                    {
                        "package": package,
                        "n_files": len(files),
                        "files": _summarize_files(files),
                    }
                )

        class ClassifyFilesTool(BaseTool):
            name: str = "classify_python_files"
            description: str = "Run the fine-tuned CodeBERT classifier over selected files."
            args_schema: type[BaseModel] = ClassifyInput
            _pipeline: LampsCrewPipeline = PrivateAttr()

            def __init__(self, pipeline: LampsCrewPipeline) -> None:
                super().__init__()
                self._pipeline = pipeline

            def _run(self, package: str) -> str:
                if not package:
                    fetch = self._pipeline._state.get("fetch")
                    if fetch is not None:
                        package = fetch.package
                files = self._pipeline._state.get("files")
                if files is None:
                    raise RuntimeError("No extracted files in CrewAI state.")
                classifications = self._pipeline.classifier.classify_files(files)
                self._pipeline._state["classifications"] = classifications
                return json.dumps(
                    {
                        "package": package,
                        "n_files": len(classifications),
                        "predictions": [
                            {
                                "path": c.rel_path,
                                "label": c.label,
                                "target": c.target,
                                "score": c.score,
                            }
                            for c in classifications
                        ],
                    }
                )

        class AggregateVerdictTool(BaseTool):
            name: str = "aggregate_package_verdict"
            description: str = "Apply conservative aggregation and produce the package verdict."
            args_schema: type[BaseModel] = VerdictInput
            _pipeline: LampsCrewPipeline = PrivateAttr()

            def __init__(self, pipeline: LampsCrewPipeline) -> None:
                super().__init__()
                self._pipeline = pipeline

            def _run(self, package: str) -> str:
                if not package:
                    fetch = self._pipeline._state.get("fetch")
                    if fetch is not None:
                        package = fetch.package
                classifications = self._pipeline._state.get("classifications")
                if classifications is None:
                    raise RuntimeError("No classifications in CrewAI state.")
                verdict = self._pipeline.verdict.aggregate(package, classifications)
                self._pipeline._state["verdict"] = verdict
                return json.dumps(verdict.to_dict(), ensure_ascii=False)

        return {
            "fetch": FetchPackageTool(pipeline),
            "extract": ExtractPythonFilesTool(pipeline),
            "classify": ClassifyFilesTool(pipeline),
            "verdict": AggregateVerdictTool(pipeline),
        }

    # ------------------------------------------------------------------
    # Auditable execution using the same role order as the CrewAI crew.
    # ------------------------------------------------------------------
    def analyze_package(
        self, package: str, version: Optional[str] = None
    ) -> LampsCrewResult:
        """Run the four paper agents and record a CrewAI-style trace."""
        steps: list[CrewAIStep] = []

        fetch_result = self.fetcher.fetch(package, version=version)
        steps.append(
            CrewAIStep(
                agent="Fetcher Agent",
                action="fetch",
                output={
                    "package": fetch_result.package,
                    "version": fetch_result.version,
                    "archive_path": str(fetch_result.archive_path),
                    "archive_url": fetch_result.archive_url,
                },
            )
        )

        files = self.extractor.extract(fetch_result.archive_path, package)
        steps.append(
            CrewAIStep(
                agent="Extractor Agent",
                action="extract",
                output={"n_files": len(files), "files": _summarize_files(files)},
            )
        )

        classifications = self.classifier.classify_files(files)
        steps.append(
            CrewAIStep(
                agent="Classifier Agent",
                action="classify",
                output={
                    "n_files": len(classifications),
                    "n_malicious": sum(1 for c in classifications if c.target == 1),
                    "predictions": [
                        {
                            "path": c.rel_path,
                            "label": c.label,
                            "target": c.target,
                            "score": c.score,
                        }
                        for c in classifications
                    ],
                },
            )
        )

        verdict = self.verdict.aggregate(package, classifications)
        steps.append(
            CrewAIStep(
                agent="Verdict Agent",
                action="aggregate",
                output=verdict.to_dict(),
            )
        )

        self.last_execution = CrewAIExecution(package=package, steps=steps)
        return LampsCrewResult(
            package=package,
            verdict=verdict,
            fetch=fetch_result,
            files=classifications,
        )

    def analyze_local_archive(
        self, archive_path: Path, package: str
    ) -> LampsCrewResult:
        """Run Extractor -> Classifier -> Verdict for a local archive."""
        steps: list[CrewAIStep] = [
            CrewAIStep(
                agent="Fetcher Agent",
                action="skip_local_archive",
                output={"archive_path": str(archive_path), "package": package},
            )
        ]

        files = self.extractor.extract(archive_path, package)
        steps.append(
            CrewAIStep(
                agent="Extractor Agent",
                action="extract",
                output={"n_files": len(files), "files": _summarize_files(files)},
            )
        )

        classifications = self.classifier.classify_files(files)
        steps.append(
            CrewAIStep(
                agent="Classifier Agent",
                action="classify",
                output={
                    "n_files": len(classifications),
                    "n_malicious": sum(1 for c in classifications if c.target == 1),
                },
            )
        )

        verdict = self.verdict.aggregate(package, classifications)
        steps.append(
            CrewAIStep(
                agent="Verdict Agent",
                action="aggregate",
                output=verdict.to_dict(),
            )
        )

        self.last_execution = CrewAIExecution(package=package, steps=steps)
        return LampsCrewResult(package=package, verdict=verdict, fetch=None, files=classifications)
