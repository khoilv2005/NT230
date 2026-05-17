"""End-to-end LAMPS pipeline (paper §3).

Coordinates the four role-specialised agents to produce a package-level
malicious/benign verdict for a given PyPI package or for an already-extracted
multi-file dataset record.

The implementation supports two execution modes:

* **Live mode** — fetch the package from PyPI, extract its archive, classify
  each Python file, and aggregate the verdict. Used by the demo CLI in
  ``hybrid_pypi_classifier.py``.
* **Offline mode** — accept a list of files that have already been extracted
  (for example from D2 records produced by ``prepare_d2.py``). Used by the
  RQ2 / RQ3 evaluators.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from lamps.agents.classifier import ClassifierAgent, FileClassification
from lamps.agents.extractor import ExtractedFile, ExtractorAgent
from lamps.agents.fetcher import FetcherAgent, FetchResult
from lamps.agents.verdict import PackageVerdict, VerdictAgent


@dataclass
class LampsResult:
    package: str
    verdict: PackageVerdict
    fetch: Optional[FetchResult] = None
    files: list[FileClassification] = None  # type: ignore[assignment]

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
                    "label": f.label,
                    "score": f.score,
                }
                for f in (self.files or [])
            ],
        }


class LampsPipeline:
    """High-level controller for the four-agent LAMPS workflow."""

    def __init__(
        self,
        fetcher: Optional[FetcherAgent] = None,
        extractor: Optional[ExtractorAgent] = None,
        classifier: Optional[ClassifierAgent] = None,
        verdict: Optional[VerdictAgent] = None,
    ) -> None:
        self.fetcher = fetcher or FetcherAgent()
        self.extractor = extractor or ExtractorAgent()
        self.classifier = classifier or ClassifierAgent()
        self.verdict = verdict or VerdictAgent()

    # ------------------------------------------------------------------
    # Live mode
    # ------------------------------------------------------------------
    def analyze_package(
        self, package: str, version: Optional[str] = None
    ) -> LampsResult:
        """Fetch ``package`` from PyPI and classify every file inside it."""
        fetch_result = self.fetcher.fetch(package, version=version)
        files = self.extractor.extract(fetch_result.archive_path, package)
        classifications = self.classifier.classify_files(files)
        verdict = self.verdict.aggregate(package, classifications)
        return LampsResult(
            package=package,
            verdict=verdict,
            fetch=fetch_result,
            files=classifications,
        )

    # ------------------------------------------------------------------
    # Offline mode (used by the dataset evaluators)
    # ------------------------------------------------------------------
    def analyze_files(
        self,
        package: str,
        files: Iterable[ExtractedFile],
    ) -> LampsResult:
        """Classify already-extracted files and aggregate the verdict."""
        files_list = list(files)
        classifications = self.classifier.classify_files(files_list)
        verdict = self.verdict.aggregate(package, classifications)
        return LampsResult(
            package=package,
            verdict=verdict,
            fetch=None,
            files=classifications,
        )

    # ------------------------------------------------------------------
    def analyze_local_archive(
        self, archive_path: Path, package: str
    ) -> LampsResult:
        """Skip the fetch step and run on a pre-downloaded archive."""
        files = self.extractor.extract(archive_path, package)
        classifications = self.classifier.classify_files(files)
        verdict = self.verdict.aggregate(package, classifications)
        return LampsResult(
            package=package,
            verdict=verdict,
            fetch=None,
            files=classifications,
        )
