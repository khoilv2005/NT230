"""Fetcher Agent (paper §3.1).

Resolves a PyPI package name to its source archive URL and downloads the
sdist. The agent uses an LLM only as a thin reasoning layer for ambiguous
inputs; the actual network operations are deterministic Python code so the
output remains auditable across runs.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import requests

from lamps.config import DOWNLOADS_DIR


@dataclass
class FetchResult:
    package: str
    version: str
    archive_path: Path
    archive_url: str


class FetcherAgent:
    """Resolves and downloads PyPI source distributions."""

    def __init__(
        self,
        download_dir: Path = DOWNLOADS_DIR,
        timeout: float = 30.0,
    ) -> None:
        self.download_dir = Path(download_dir)
        self.download_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout

    # ------------------------------------------------------------------
    def resolve_sdist_url(
        self, package: str, version: Optional[str] = None
    ) -> tuple[str, str]:
        """Return ``(version, sdist_url)`` for ``package``.

        If ``version`` is None, the latest available stable version is used.
        """
        if version:
            url = f"https://pypi.org/pypi/{package}/{version}/json"
        else:
            url = f"https://pypi.org/pypi/{package}/json"

        response = requests.get(url, timeout=self.timeout)
        response.raise_for_status()
        meta = response.json()

        resolved_version = meta["info"]["version"]
        for entry in meta.get("urls", []):
            if entry.get("packagetype") == "sdist":
                return resolved_version, entry["url"]

        raise RuntimeError(
            f"No source distribution available for {package}=={resolved_version}"
        )

    # ------------------------------------------------------------------
    def download(self, url: str) -> Path:
        """Stream the archive at ``url`` to disk and return the local path."""
        local_name = url.split("/")[-1]
        target = self.download_dir / local_name
        if target.exists():
            return target

        with requests.get(url, stream=True, timeout=self.timeout) as r:
            r.raise_for_status()
            with open(target, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
        return target

    # ------------------------------------------------------------------
    def fetch(
        self, package: str, version: Optional[str] = None
    ) -> FetchResult:
        """Resolve the package metadata and download its sdist."""
        resolved_version, archive_url = self.resolve_sdist_url(package, version)
        archive_path = self.download(archive_url)
        return FetchResult(
            package=package,
            version=resolved_version,
            archive_path=archive_path,
            archive_url=archive_url,
        )
