"""Extractor Agent (paper §3.1).

Unpacks a PyPI source archive and selects the Python files that should be
classified. Tests, generated code, and known-noisy paths are excluded so the
classifier focuses on executable code paths where malicious logic is most
likely to live.
"""

from __future__ import annotations

import shutil
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from lamps.config import EXTRACTED_DIR


# Paths whose name segments suggest non-executable content. The paper notes
# that documentation, tests and configuration files should be skipped.
_NOISY_DIR_TOKENS = {
    "tests",
    "test",
    "testing",
    "docs",
    "doc",
    "examples",
    "example",
    "_vendor",
    "vendor",
}
_NOISY_FILENAME_PREFIXES = ("test_",)
_NOISY_FILENAME_SUFFIXES = ("_test.py",)


@dataclass
class ExtractedFile:
    package: str
    path: Path           # absolute path on disk
    rel_path: str        # path relative to the package root
    source: str          # file contents


class ExtractorAgent:
    """Unpacks PyPI archives and yields the Python files to classify."""

    def __init__(
        self,
        extract_dir: Path = EXTRACTED_DIR,
        keep_extracted: bool = True,
    ) -> None:
        self.extract_dir = Path(extract_dir)
        self.extract_dir.mkdir(parents=True, exist_ok=True)
        self.keep_extracted = keep_extracted

    # ------------------------------------------------------------------
    def _extract_archive(self, archive_path: Path, target: Path) -> None:
        target.mkdir(parents=True, exist_ok=True)
        suffixes = "".join(archive_path.suffixes).lower()
        if suffixes.endswith(".tar.gz") or suffixes.endswith(".tgz"):
            with tarfile.open(archive_path, "r:gz") as tar:
                tar.extractall(path=target)
        elif suffixes.endswith(".zip") or archive_path.suffix.lower() == ".whl":
            with zipfile.ZipFile(archive_path, "r") as zf:
                zf.extractall(path=target)
        elif suffixes.endswith(".tar"):
            with tarfile.open(archive_path, "r:") as tar:
                tar.extractall(path=target)
        else:
            raise ValueError(f"Unsupported archive type: {archive_path}")

    # ------------------------------------------------------------------
    def _is_relevant(self, rel_path: Path) -> bool:
        parts = {p.lower() for p in rel_path.parts}
        if parts & _NOISY_DIR_TOKENS:
            return False
        name = rel_path.name.lower()
        if name.startswith(_NOISY_FILENAME_PREFIXES):
            return False
        if name.endswith(_NOISY_FILENAME_SUFFIXES):
            return False
        return True

    # ------------------------------------------------------------------
    def _read_source(self, path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return ""

    # ------------------------------------------------------------------
    def extract(self, archive_path: Path, package: str) -> list[ExtractedFile]:
        """Extract ``archive_path`` and return relevant ``.py`` files."""
        archive_path = Path(archive_path)
        if self.keep_extracted:
            target_root = self.extract_dir / archive_path.stem.replace(".tar", "")
            if target_root.exists():
                shutil.rmtree(target_root)
            target_root.mkdir(parents=True)
        else:
            target_root = Path(tempfile.mkdtemp(prefix="lamps_extract_"))

        try:
            self._extract_archive(archive_path, target_root)

            # Most sdists extract into a single nested directory. Walk to find
            # the package root if such a directory exists.
            children = [c for c in target_root.iterdir() if c.is_dir()]
            package_root = children[0] if len(children) == 1 else target_root

            results: list[ExtractedFile] = []
            for path in sorted(package_root.rglob("*.py")):
                if not path.is_file():
                    continue
                rel_path = path.relative_to(package_root)
                if not self._is_relevant(rel_path):
                    continue
                source = self._read_source(path)
                if not source.strip():
                    continue
                results.append(
                    ExtractedFile(
                        package=package,
                        path=path.resolve(),
                        rel_path=rel_path.as_posix(),
                        source=source,
                    )
                )
            return results
        finally:
            if not self.keep_extracted:
                shutil.rmtree(target_root, ignore_errors=True)

    # ------------------------------------------------------------------
    def filter_files(
        self, files: Iterable[ExtractedFile], top_k: Optional[int] = None
    ) -> list[ExtractedFile]:
        """Return at most ``top_k`` files. ``setup.py`` is always kept first.

        Used by the SA-TopK baseline to bound the prompt budget.
        """
        files = list(files)
        if top_k is None:
            return files

        # Prioritise setup.py and __init__.py, then larger files (more code).
        def priority(f: ExtractedFile) -> tuple[int, int]:
            name = f.rel_path.lower()
            if name == "setup.py":
                key = 0
            elif name.endswith("__init__.py"):
                key = 1
            else:
                key = 2
            return (key, -len(f.source))

        files.sort(key=priority)
        return files[:top_k]


# ---------------------------------------------------------------------------
# LLM-based semantic file selector (paper §3.1 — Extractor Agent with LLaMA-3)
# ---------------------------------------------------------------------------

_EXTRACTOR_PROMPT = """\
You are the Extractor Agent in the LAMPS malicious-package detection pipeline.

Given the list of Python files in package '{package}', select ONLY the files \
that should be analysed for potential malicious behaviour.

Rules:
- KEEP: setup.py, __init__.py, main modules, utility modules, any file that \
could contain installation-time or import-time code execution.
- EXCLUDE: test files (test_*.py, *_test.py), documentation scripts, \
configuration-only files, migration files, generated code.

Respond with a JSON array of file paths to keep, e.g.:
["setup.py", "mypackage/__init__.py", "mypackage/utils.py"]

Files in package '{package}':
{file_list}
"""


class LLMExtractorAgent:
    """Extractor Agent backed by an LLM for semantic file selection (paper §3.1).

    Falls back to rule-based filtering when the LLM response cannot be parsed.
    """

    def __init__(self, llm: object) -> None:
        self.llm = llm

    def _call_llm(self, prompt: str) -> str:
        if hasattr(self.llm, "generate"):
            return self.llm.generate(prompt).text
        if callable(self.llm):
            return self.llm(prompt)
        if hasattr(self.llm, "run"):
            return self.llm.run(prompt)
        raise TypeError("Unsupported LLM interface")

    def filter(
        self,
        package: str,
        files: list["ExtractedFile"],
    ) -> list["ExtractedFile"]:
        """Use the LLM to select relevant files from ``files``."""
        import json, re

        if not files:
            return files

        file_list = "\n".join(f"- {f.rel_path}" for f in files)
        prompt = _EXTRACTOR_PROMPT.format(package=package, file_list=file_list)

        try:
            raw = self._call_llm(prompt)
            # Extract JSON array from response
            match = re.search(r"\[.*?\]", raw, re.DOTALL)
            if match:
                selected_paths = set(json.loads(match.group(0)))
                filtered = [f for f in files if f.rel_path in selected_paths]
                if filtered:
                    return filtered
        except Exception:
            pass

        # Fallback: rule-based
        extractor = ExtractorAgent()
        return [f for f in files if extractor._is_relevant(Path(f.rel_path))]
