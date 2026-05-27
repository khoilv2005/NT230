from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import shutil
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from build_setup_py_dataset import OUT, extract_setup_from_tar, extract_setup_from_zip


TOP_PYPI_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
PYPI_JSON_URL = "https://pypi.org/pypi/{project}/json"
USER_AGENT = "lamps-jss-benign-setup-py-builder/1.0"


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def urlopen_bytes(url: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def top_pypi_projects() -> list[dict[str, object]]:
    data = json.loads(urlopen_bytes(TOP_PYPI_URL).decode("utf-8"))
    return list(data["rows"])


def malicious_names() -> set[str]:
    names: set[str] = set()
    manifest = OUT / "manifest.csv"
    if not manifest.exists():
        return names
    with manifest.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            source = row["source_archive"].replace("\\", "/")
            parts = source.split("/")
            if row["dataset"] == "datadog_pypi" and len(parts) >= 2:
                names.add(normalize_name(parts[1]))
            elif row["dataset"] == "pypi_malregistry" and parts:
                names.add(normalize_name(parts[0]))
    return names


def safe_id(project: str, version: str, filename: str) -> str:
    raw = f"top_pypi/{project}/{version}/{filename}"
    digest = hashlib.sha1(raw.encode("utf-8", "surrogateescape")).hexdigest()[:12]
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in raw)
    safe = safe.strip("._-")[:130]
    return f"top_pypi__{safe}__{digest}"


def select_sdist(project: str) -> tuple[str, str, str] | None:
    data = json.loads(urlopen_bytes(PYPI_JSON_URL.format(project=project)).decode("utf-8"))
    version = str(data["info"]["version"])
    candidates = [item for item in data.get("urls", []) if item.get("packagetype") == "sdist"]
    if not candidates:
        return None
    candidates.sort(key=lambda item: int(item.get("size") or 0))
    item = candidates[0]
    return version, str(item["filename"]), str(item["url"])


def extract_setup(filename: str, data: bytes) -> tuple[str, bytes] | None:
    lower = filename.lower()
    if data.startswith(b"PK\x03\x04") or lower.endswith((".zip", ".whl")):
        return extract_setup_from_zip(data)
    if lower.endswith((".tar.gz", ".tgz", ".tar", ".tar.bz2", ".tar.xz")):
        return extract_setup_from_tar(data)
    return None


def process_project(project: str, rank: int, download_count: int, deny: set[str]) -> dict[str, str]:
    norm = normalize_name(project)
    if norm in deny:
        return {"status": "skipped_malicious_name", "project": project}
    try:
        selected = select_sdist(project)
        if selected is None:
            return {"status": "skipped_no_sdist", "project": project}
        version, filename, url = selected
        data = urlopen_bytes(url, timeout=60)
        found = extract_setup(filename, data)
        if found is None:
            return {"status": "skipped_no_setup_py", "project": project, "version": version, "filename": filename}
        setup_member, setup_bytes = found
        sample_id = safe_id(project, version, filename)
        dst_dir = OUT / "benign" / sample_id
        dst_dir.mkdir(parents=True, exist_ok=True)
        (dst_dir / "setup.py").write_bytes(setup_bytes)
        return {
            "status": "written",
            "sample_id": sample_id,
            "label": "benign",
            "dataset": "top_pypi",
            "project": project,
            "normalized_project": norm,
            "version": version,
            "rank": str(rank),
            "download_count": str(download_count),
            "source_archive": url,
            "setup_member": setup_member,
            "output": str(dst_dir / "setup.py"),
        }
    except (urllib.error.URLError, TimeoutError, ValueError, OSError, RuntimeError, EOFError) as exc:
        return {"status": "error", "project": project, "error": repr(exc)}


def write_existing_and_benign_manifest(benign_rows: list[dict[str, str]]) -> None:
    manifest = OUT / "manifest.csv"
    old_rows: list[dict[str, str]] = []
    if manifest.exists():
        with manifest.open(newline="", encoding="utf-8") as f:
            old_rows = [row for row in csv.DictReader(f) if row.get("label") != "benign"]
    fieldnames = ["sample_id", "label", "dataset", "source_archive", "setup_member", "output"]
    with manifest.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(old_rows)
        writer.writerows(benign_rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=int, default=0, help="Benign setup.py count target. Default: match malicious count.")
    parser.add_argument("--workers", type=int, default=12)
    parser.add_argument("--limit", type=int, default=15000)
    args = parser.parse_args()

    benign_dir = OUT / "benign"
    malicious_dir = OUT / "malicious"
    if not malicious_dir.exists():
        print(f"Missing malicious dir: {malicious_dir}", file=sys.stderr)
        return 1
    if benign_dir.exists():
        shutil.rmtree(benign_dir)
    benign_dir.mkdir(parents=True, exist_ok=True)

    target = args.target or sum(1 for item in malicious_dir.iterdir() if item.is_dir())
    projects = top_pypi_projects()[: args.limit]
    deny = malicious_names()
    benign_rows: list[dict[str, str]] = []
    status_counts: dict[str, int] = {}
    started = time.time()

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(
                process_project,
                str(row["project"]),
                idx,
                int(row.get("download_count") or 0),
                deny,
            ): str(row["project"])
            for idx, row in enumerate(projects, start=1)
        }
        for done, future in enumerate(as_completed(futures), start=1):
            result = future.result()
            status = result.pop("status")
            status_counts[status] = status_counts.get(status, 0) + 1
            if status == "written":
                benign_rows.append(result)
            if len(benign_rows) >= target:
                for pending in futures:
                    pending.cancel()
                break
            if done % 250 == 0:
                elapsed = time.time() - started
                print(json.dumps({"checked": done, "written": len(benign_rows), "elapsed_sec": round(elapsed, 1)}), flush=True)

    write_existing_and_benign_manifest(benign_rows)
    summary = {
        "target": target,
        "written": len(benign_rows),
        "status_counts": status_counts,
        "top_pypi_limit": args.limit,
        "workers": args.workers,
    }
    (OUT / "benign_top_pypi_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
