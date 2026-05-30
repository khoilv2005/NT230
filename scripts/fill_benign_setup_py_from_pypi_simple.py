from __future__ import annotations

import argparse
import csv
import html.parser
import json
import random
import re
import time
import urllib.error
import urllib.request
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path

from add_benign_setup_py_from_top_pypi import (
    PYPI_JSON_URL,
    USER_AGENT,
    extract_setup,
    malicious_names,
    safe_id,
    select_sdist,
    urlopen_bytes,
)
from build_setup_py_dataset import OUT

SIMPLE_URL = "https://pypi.org/simple/"
PROGRESS_CSV = OUT / "benign_pypi_simple_added.csv"


class SimpleIndexParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.names: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return
        for key, value in attrs:
            if key == "href" and value:
                name = value.strip("/").rsplit("/", 1)[-1]
                if name:
                    self.names.append(name)


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def simple_projects(seed: int) -> list[str]:
    parser = SimpleIndexParser()
    parser.feed(urlopen_bytes(SIMPLE_URL, timeout=120).decode("utf-8", "replace"))
    names = sorted(set(parser.names))
    random.Random(seed).shuffle(names)
    return names


def actual_benign_count() -> int:
    benign_dir = OUT / "benign"
    if not benign_dir.exists():
        return 0
    return sum(1 for path in benign_dir.iterdir() if path.is_dir() and (path / "setup.py").exists())


def existing_sample_ids() -> set[str]:
    benign_dir = OUT / "benign"
    if not benign_dir.exists():
        return set()
    return {path.name for path in benign_dir.iterdir() if path.is_dir() and (path / "setup.py").exists()}


def load_progress_rows() -> list[dict[str, str]]:
    if not PROGRESS_CSV.exists():
        return []
    with PROGRESS_CSV.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def append_progress(row: dict[str, str]) -> None:
    exists = PROGRESS_CSV.exists()
    fieldnames = ["sample_id", "label", "dataset", "source_archive", "setup_member", "output"]
    with PROGRESS_CSV.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        if not exists:
            writer.writeheader()
        writer.writerow(row)


def process_project(project: str, deny: set[str], existing_ids: set[str]) -> dict[str, str]:
    norm = normalize_name(project)
    if norm in deny:
        return {"status": "skipped_malicious_name", "project": project}
    try:
        selected = select_sdist(project)
        if selected is None:
            return {"status": "skipped_no_sdist", "project": project}
        version, filename, url = selected
        sample_id = safe_id(project, version, filename)
        if sample_id in existing_ids:
            return {"status": "skipped_existing", "project": project, "sample_id": sample_id}
        data = urlopen_bytes(url, timeout=60)
        found = extract_setup(filename, data)
        if found is None:
            return {"status": "skipped_no_setup_py", "project": project, "version": version, "filename": filename}
        setup_member, setup_bytes = found
        dst_dir = OUT / "benign" / sample_id
        dst_dir.mkdir(parents=True, exist_ok=True)
        (dst_dir / "setup.py").write_bytes(setup_bytes)
        return {
            "status": "written",
            "sample_id": sample_id,
            "label": "benign",
            "dataset": "pypi_simple",
            "source_archive": url,
            "setup_member": setup_member,
            "output": str(dst_dir / "setup.py"),
        }
    except (urllib.error.URLError, TimeoutError, ValueError, OSError, RuntimeError, EOFError) as exc:
        return {"status": "error", "project": project, "error": repr(exc)}


def rebuild_manifest() -> None:
    manifest = OUT / "manifest.csv"
    malicious_rows: list[dict[str, str]] = []
    benign_rows_by_id: dict[str, dict[str, str]] = {}
    if manifest.exists():
        with manifest.open(newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                if row.get("label") == "malicious":
                    malicious_rows.append(row)
                elif row.get("label") == "benign" and row.get("sample_id"):
                    output = row.get("output", "")
                    if output and Path(output).exists():
                        benign_rows_by_id.setdefault(row["sample_id"], row)
    for row in load_progress_rows():
        if row.get("sample_id") and Path(row.get("output", "")).exists():
            benign_rows_by_id[row["sample_id"]] = row
    for sample_dir in (OUT / "benign").iterdir():
        setup_path = sample_dir / "setup.py"
        if sample_dir.is_dir() and setup_path.exists() and sample_dir.name not in benign_rows_by_id:
            benign_rows_by_id[sample_dir.name] = {
                "sample_id": sample_dir.name,
                "label": "benign",
                "dataset": "top_pypi",
                "source_archive": "",
                "setup_member": "setup.py",
                "output": str(setup_path),
            }
    fieldnames = ["sample_id", "label", "dataset", "source_archive", "setup_member", "output"]
    with manifest.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(malicious_rows)
        writer.writerows(benign_rows_by_id.values())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=int, required=True)
    parser.add_argument("--workers", type=int, default=24)
    parser.add_argument("--seed", type=int, default=230)
    parser.add_argument("--max-projects", type=int, default=120000)
    parser.add_argument("--inflight", type=int, default=300)
    args = parser.parse_args()

    (OUT / "benign").mkdir(parents=True, exist_ok=True)
    deny = malicious_names()
    existing_ids = existing_sample_ids()
    status_counts: dict[str, int] = {}
    written_start = actual_benign_count()
    projects = simple_projects(args.seed)
    checked = 0
    started = time.time()

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        pending = set()
        iterator = (p for p in projects if normalize_name(p) not in deny)
        while actual_benign_count() < args.target and checked < args.max_projects:
            while len(pending) < args.inflight and checked < args.max_projects:
                try:
                    project = next(iterator)
                except StopIteration:
                    break
                checked += 1
                pending.add(executor.submit(process_project, project, deny, existing_ids))
            if not pending:
                break
            done, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                result = future.result()
                status = result.pop("status")
                status_counts[status] = status_counts.get(status, 0) + 1
                if status == "written":
                    existing_ids.add(result["sample_id"])
                    append_progress(result)
            if checked % 1000 == 0:
                print(
                    json.dumps(
                        {
                            "checked": checked,
                            "benign": actual_benign_count(),
                            "elapsed_sec": round(time.time() - started, 1),
                        }
                    ),
                    flush=True,
                )

    rebuild_manifest()
    summary = {
        "target": args.target,
        "start_count": written_start,
        "final_count": actual_benign_count(),
        "new_written": max(0, actual_benign_count() - written_start),
        "checked": checked,
        "status_counts": status_counts,
        "seed": args.seed,
        "max_projects": args.max_projects,
    }
    (OUT / "benign_pypi_simple_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0 if summary["final_count"] >= args.target else 2


if __name__ == "__main__":
    raise SystemExit(main())
