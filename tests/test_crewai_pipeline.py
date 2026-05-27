from __future__ import annotations

import sys
import unittest
from dataclasses import dataclass, field
from importlib.util import find_spec
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lamps.crewai_pipeline import LampsCrewPipeline


@dataclass
class FakeFetchResult:
    package: str
    version: str
    archive_path: Path
    archive_url: str


@dataclass
class FakeExtractedFile:
    package: str
    path: Path
    rel_path: str
    source: str


@dataclass
class FakeClassification:
    package: str
    rel_path: str
    label: str
    target: int
    score: float


@dataclass
class FakeVerdict:
    package: str
    label: str
    target: int
    malicious_files: list[FakeClassification] = field(default_factory=list)
    benign_files: list[FakeClassification] = field(default_factory=list)
    rationale: str = "fake rationale"

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
                {"path": f.rel_path, "score": f.score}
                for f in self.malicious_files
            ],
            "rationale": self.rationale,
        }


class FakeFetcher:
    def fetch(self, package: str, version: str | None = None) -> FakeFetchResult:
        return FakeFetchResult(
            package=package,
            version=version or "1.0.0",
            archive_path=Path("pkg-1.0.0.tar.gz"),
            archive_url="https://example.test/pkg-1.0.0.tar.gz",
        )


class FakeExtractor:
    def extract(self, archive_path: Path, package: str) -> list[FakeExtractedFile]:
        return [
            FakeExtractedFile(
                package=package,
                path=Path("setup.py"),
                rel_path="setup.py",
                source="import os\nos.system('echo test')",
            )
        ]


class FakeClassifier:
    def classify_files(self, files: list[FakeExtractedFile]) -> list[FakeClassification]:
        return [
            FakeClassification(
                package=f.package,
                rel_path=f.rel_path,
                label="malicious",
                target=1,
                score=0.99,
            )
            for f in files
        ]


class FakeVerdictAgent:
    def aggregate(
        self,
        package: str,
        predictions: list[FakeClassification],
    ) -> FakeVerdict:
        malicious = [p for p in predictions if p.target == 1]
        benign = [p for p in predictions if p.target == 0]
        return FakeVerdict(
            package=package,
            label="malicious" if malicious else "benign",
            target=1 if malicious else 0,
            malicious_files=malicious,
            benign_files=benign,
        )


class LampsCrewPipelineTest(unittest.TestCase):
    def test_analyze_package_records_four_paper_agents(self) -> None:
        pipeline = LampsCrewPipeline(
            fetcher=FakeFetcher(),
            extractor=FakeExtractor(),
            classifier=FakeClassifier(),
            verdict=FakeVerdictAgent(),
        )

        result = pipeline.analyze_package("demo", version="1.2.3")

        self.assertEqual(result.verdict.target, 1)
        self.assertIsNotNone(pipeline.last_execution)
        self.assertEqual(
            [step.agent for step in pipeline.last_execution.steps],
            [
                "Fetcher Agent",
                "Extractor Agent",
                "Classifier Agent",
                "Verdict Agent",
            ],
        )
        self.assertEqual(
            [step.action for step in pipeline.last_execution.steps],
            ["fetch", "extract", "classify", "aggregate"],
        )

    @unittest.skipIf(find_spec("crewai") is None, "CrewAI not installed")
    def test_build_crew_defines_four_agents_and_tasks(self) -> None:
        pipeline = LampsCrewPipeline(
            fetcher=FakeFetcher(),
            extractor=FakeExtractor(),
            classifier=FakeClassifier(),
            verdict=FakeVerdictAgent(),
        )

        crew = pipeline.build_crew()

        self.assertEqual(len(crew.agents), 4)
        self.assertEqual(len(crew.tasks), 4)
        self.assertEqual(
            [agent.role for agent in crew.agents],
            [
                "Fetcher Agent",
                "Extractor Agent",
                "Classifier Agent",
                "Verdict Agent",
            ],
        )


if __name__ == "__main__":
    unittest.main()
