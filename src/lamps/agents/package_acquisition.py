"""Package Acquisition Agent for TRACE-LAMPS."""

from __future__ import annotations

import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Iterable

from lamps.agents.extractor import ExtractedFile
from lamps.agents.fetcher import FetcherAgent, FetchResult
from lamps.config import EXTRACTED_DIR


class PackageAcquisitionAgent:
    """Fetch source archives and extract Python files with relative paths."""

    def __init__(
        self,
        fetcher: FetcherAgent | None = None,
        extract_dir: Path = EXTRACTED_DIR,
        keep_extracted: bool = True,
        include_all_python: bool = True,
    ) -> None:
        self.fetcher = fetcher or FetcherAgent()
        self.extract_dir = Path(extract_dir)
        self.extract_dir.mkdir(parents=True, exist_ok=True)
        self.keep_extracted = keep_extracted
        self.include_all_python = include_all_python

    def acquire(
        self, package: str, version: str | None = None
    ) -> tuple[FetchResult, list[ExtractedFile]]:
        fetch = self.fetcher.fetch(package, version=version)
        return fetch, self.extract(fetch.archive_path, package)

    def extract(self, archive_path: Path, package: str) -> list[ExtractedFile]:
        archive_path = Path(archive_path)
        if self.keep_extracted:
            target_root = self.extract_dir / archive_path.name.replace(".tar.gz", "").replace(".tgz", "").replace(".zip", "").replace(".whl", "")
            if target_root.exists():
                shutil.rmtree(target_root)
            target_root.mkdir(parents=True)
        else:
            target_root = Path(tempfile.mkdtemp(prefix="trace_lamps_extract_"))

        try:
            self._extract_archive(archive_path, target_root)
            package_root = self._package_root(target_root)
            files = []
            for path in sorted(package_root.rglob("*.py")):
                if not path.is_file():
                    continue
                rel_path = path.relative_to(package_root)
                if not self._is_relevant(rel_path):
                    continue
                source = self._read_source(path)
                if not source.strip():
                    continue
                files.append(
                    ExtractedFile(
                        package=package,
                        path=path.resolve(),
                        rel_path=rel_path.as_posix(),
                        source=source,
                    )
                )
            return files
        finally:
            if not self.keep_extracted:
                shutil.rmtree(target_root, ignore_errors=True)

    def from_files(
        self, package: str, files: Iterable[ExtractedFile]
    ) -> list[ExtractedFile]:
        return list(files)

    def _extract_archive(self, archive_path: Path, target: Path) -> None:
        suffixes = "".join(archive_path.suffixes).lower()
        if suffixes.endswith(".tar.gz") or suffixes.endswith(".tgz"):
            with tarfile.open(archive_path, "r:gz") as tar:
                tar.extractall(path=target)
        elif suffixes.endswith(".tar"):
            with tarfile.open(archive_path, "r:") as tar:
                tar.extractall(path=target)
        elif suffixes.endswith(".zip") or archive_path.suffix.lower() == ".whl":
            with zipfile.ZipFile(archive_path, "r") as zf:
                zf.extractall(path=target)
        else:
            raise ValueError(f"Unsupported archive type: {archive_path}")

    def _package_root(self, target_root: Path) -> Path:
        children = [c for c in target_root.iterdir() if c.is_dir()]
        return children[0] if len(children) == 1 else target_root

    def _is_relevant(self, rel_path: Path) -> bool:
        if self.include_all_python:
            return True
        parts = {p.lower() for p in rel_path.parts}
        noisy = {"docs", "doc", "examples", "example", "tests", "test", "testing"}
        name = rel_path.name.lower()
        if parts & noisy:
            return False
        return not (name.startswith("test_") or name.endswith("_test.py"))

    def _read_source(self, path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return ""
