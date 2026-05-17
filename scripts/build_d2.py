"""Build the D2 multi-file dataset (paper §4.2.2).

Cấu trúc DataDog repo:
  samples/pypi/malicious_intent/<pkg>/<version>/<date>-<pkg>-v<version>.zip
  (mỗi ZIP được mã hoá, password: "infected")

Pipeline:
  1. Đọc manifest.json để lấy danh sách package names
  2. Với mỗi package: tìm ZIP file qua GitHub Contents API, download, giải mã
  3. Download top PyPI packages làm benign
  4. Ghi data/d2/raw/ + labels.csv
  5. Chạy prepare_d2.py → files.jsonl, packages.jsonl

Usage:
    python scripts/build_d2.py
    python scripts/build_d2.py --max-malicious 50 --max-benign 100
    python scripts/build_d2.py --github-token <token>   # tránh rate limit
"""

from __future__ import annotations

import argparse
import csv
import io
import os
import shutil
import sys
import tarfile
import time
import zipfile
from pathlib import Path

import requests
from tqdm import tqdm

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

# Auto-load .env (picks up GITHUB_TOKEN without exposing the value)
# Supports both standard format (KEY=value) and PowerShell format ($env:KEY = "value")
_env_file = REPO_ROOT / ".env"
if _env_file.exists():
    import re as _re
    for _line in _env_file.read_text(encoding="utf-8").splitlines():
        _line = _line.strip()
        if not _line or _line.startswith("#"):
            continue
        # PowerShell: $env:KEY = "value"
        _m = _re.match(r'^\$env:(\w+)\s*=\s*["\']?([^"\']+)["\']?', _line)
        if _m:
            os.environ.setdefault(_m.group(1), _m.group(2).strip())
            continue
        # Standard: KEY=value or KEY="value"
        if "=" in _line:
            _k, _, _v = _line.partition("=")
            os.environ.setdefault(_k.strip(), _v.strip().strip('"').strip("'"))

from lamps.utils import configure_logging, logger  # noqa: E402

D2_RAW_DIR = REPO_ROOT / "data" / "d2" / "raw"
GH_OWNER = "DataDog"
GH_REPO  = "malicious-software-packages-dataset"
ZIP_PWD  = b"infected"
TOP_PYPI_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
NOISY = {"tests", "test", "testing", "docs", "doc", "examples", "_vendor", "vendor"}


# ── GitHub helpers ──────────────────────────────────────────────────────────

def _headers(token: str | None) -> dict:
    h = {"Accept": "application/vnd.github+json"}
    tok = token or os.getenv("GITHUB_TOKEN")
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


def gh_json(url: str, token: str | None) -> dict | list:
    for attempt in range(4):
        r = requests.get(url, headers=_headers(token), timeout=30)
        if r.status_code == 403:
            wait = 60 * (attempt + 1)
            logger.warning("Rate limit. Waiting %ds …", wait)
            time.sleep(wait)
            continue
        r.raise_for_status()
        return r.json()
    raise RuntimeError(f"GitHub API failed: {url}")


def gh_raw(url: str, token: str | None) -> bytes:
    r = requests.get(url, headers=_headers(token), timeout=60)
    r.raise_for_status()
    return r.content


# ── Step 1: lấy danh sách packages từ manifest ──────────────────────────────

def get_package_names(token: str | None) -> list[str]:
    url = (f"https://raw.githubusercontent.com/{GH_OWNER}/{GH_REPO}"
           f"/main/samples/pypi/manifest.json")
    logger.info("Fetching manifest.json …")
    data = requests.get(url, timeout=15).json()
    names = sorted(data.keys())
    logger.info("Manifest: %d packages", len(names))
    return names


# ── Step 2: tìm ZIP path cho một package ────────────────────────────────────

def find_zip_path(pkg_name: str, token: str | None) -> str | None:
    """Trả về download_url của ZIP đầu tiên tìm thấy cho package."""
    # List versions
    url = (f"https://api.github.com/repos/{GH_OWNER}/{GH_REPO}"
           f"/contents/samples/pypi/malicious_intent/{pkg_name}")
    try:
        versions = gh_json(url, token)
    except Exception:
        return None

    if not isinstance(versions, list) or not versions:
        return None

    # Lấy version đầu tiên
    ver_dir = versions[0]
    if ver_dir.get("type") != "dir":
        return None

    try:
        files = gh_json(ver_dir["url"], token)
    except Exception:
        return None

    for f in files:
        if f.get("name", "").endswith(".zip"):
            return f.get("download_url")
    return None


# ── Step 3: download + giải mã + extract .py files ──────────────────────────

def extract_zip(data: bytes, dest: Path) -> list[Path]:
    dest.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            zf.extractall(path=dest, pwd=ZIP_PWD)
    except Exception as e:
        logger.debug("ZipFile error: %s", e)
        return []

    # Inner archive (.tar.gz hoặc .whl)
    for inner in list(dest.rglob("*.tar.gz")):
        try:
            with tarfile.open(inner, "r:gz") as tar:
                tar.extractall(path=dest)
        except Exception:
            pass

    for inner in list(dest.rglob("*.whl")):
        try:
            with zipfile.ZipFile(inner) as whl:
                whl.extractall(path=dest)
        except Exception:
            pass

    return _py_files(dest)


def _py_files(root: Path) -> list[Path]:
    return [
        p for p in root.rglob("*.py")
        if p.is_file()
        and not any(part.lower() in NOISY for part in p.parts)
        and not p.name.lower().startswith("test_")
        and not p.name.lower().endswith("_test.py")
    ]


def _copy(src_files: list[Path], src_root: Path, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for src in src_files:
        try:
            rel = src.relative_to(src_root)
        except ValueError:
            rel = Path(src.name)
        d = dst / rel
        d.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, d)


def safe(name: str) -> str:
    return name.replace("/", "_").replace("\\", "_").replace(" ", "_")


# ── Step 4: benign packages từ top PyPI ─────────────────────────────────────

def top_pypi_names(n: int) -> list[str]:
    logger.info("Fetching top PyPI names …")
    rows = requests.get(TOP_PYPI_URL, timeout=30).json().get("rows", [])
    return [r["project"] for r in rows[:n]]


def download_sdist(pkg: str, dl_dir: Path) -> Path | None:
    try:
        meta = requests.get(f"https://pypi.org/pypi/{pkg}/json", timeout=15).json()
    except Exception:
        return None
    for e in meta.get("urls", []):
        if e.get("packagetype") == "sdist":
            target = dl_dir / e["url"].split("/")[-1]
            if target.exists():
                return target
            try:
                with requests.get(e["url"], stream=True, timeout=60) as r:
                    r.raise_for_status()
                    with open(target, "wb") as f:
                        for chunk in r.iter_content(65536):
                            if chunk:
                                f.write(chunk)
                return target
            except Exception:
                return None
    return None


def extract_sdist(archive: Path, dest: Path) -> list[Path]:
    dest.mkdir(parents=True, exist_ok=True)
    try:
        s = "".join(archive.suffixes).lower()
        if ".tar.gz" in s or ".tgz" in s:
            with tarfile.open(archive, "r:gz") as tar:
                tar.extractall(path=dest)
        elif archive.suffix.lower() == ".zip":
            with zipfile.ZipFile(archive) as zf:
                zf.extractall(path=dest)
        else:
            return []
    except Exception:
        return []
    return _py_files(dest)


# ── Main assembly ────────────────────────────────────────────────────────────

def build(raw_dir: Path, max_mal: int, max_ben: int, token: str | None) -> dict[str, int]:
    raw_dir.mkdir(parents=True, exist_ok=True)
    tmp = raw_dir.parent / "_tmp"
    tmp.mkdir(exist_ok=True)
    labels: dict[str, int] = {}

    # ── Malicious ──
    logger.info("=== Malicious packages (DataDog) ===")
    pkg_names = get_package_names(token)[:max_mal]
    mal_ok = 0

    for name in tqdm(pkg_names, desc="Malicious"):
        dir_name = safe(name) + "-mal"
        pkg_dest = raw_dir / dir_name
        if pkg_dest.exists() and any(pkg_dest.rglob("*.py")):
            labels[dir_name] = 1
            mal_ok += 1
            continue

        zip_url = find_zip_path(name, token)
        if not zip_url:
            continue

        try:
            data = gh_raw(zip_url, token)
        except Exception as e:
            logger.debug("Download failed %s: %s", name, e)
            continue

        tmp_pkg = tmp / dir_name
        py_files = extract_zip(data, tmp_pkg)
        if not py_files:
            shutil.rmtree(tmp_pkg, ignore_errors=True)
            continue

        _copy(py_files, tmp_pkg, pkg_dest)
        shutil.rmtree(tmp_pkg, ignore_errors=True)
        labels[dir_name] = 1
        mal_ok += 1

    logger.info("Malicious done: %d packages", mal_ok)

    # ── Benign ──
    logger.info("=== Benign packages (top PyPI) ===")
    names = top_pypi_names(max_ben * 4)
    dl_dir = tmp / "_dl"
    dl_dir.mkdir(exist_ok=True)
    ben_ok = 0

    for name in tqdm(names, desc="Benign"):
        if ben_ok >= max_ben:
            break
        dir_name = safe(name)
        pkg_dest = raw_dir / dir_name
        if pkg_dest.exists() and any(pkg_dest.rglob("*.py")):
            labels[dir_name] = 0
            ben_ok += 1
            continue

        archive = download_sdist(name, dl_dir)
        if not archive:
            continue

        tmp_pkg = tmp / dir_name
        py_files = extract_sdist(archive, tmp_pkg)
        archive.unlink(missing_ok=True)
        if not py_files:
            shutil.rmtree(tmp_pkg, ignore_errors=True)
            continue

        _copy(py_files, tmp_pkg, pkg_dest)
        shutil.rmtree(tmp_pkg, ignore_errors=True)
        labels[dir_name] = 0
        ben_ok += 1

    shutil.rmtree(tmp, ignore_errors=True)

    # ── labels.csv ──
    with open(raw_dir / "labels.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["package", "label"])
        for n, l in sorted(labels.items()):
            w.writerow([n, l])

    m = sum(1 for v in labels.values() if v == 1)
    b = sum(1 for v in labels.values() if v == 0)
    logger.info("labels.csv: %d malicious, %d benign", m, b)
    return labels


# ── Entry point ──────────────────────────────────────────────────────────────

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--raw-dir", type=Path, default=D2_RAW_DIR)
    p.add_argument("--max-malicious", type=int, default=300)
    p.add_argument("--max-benign",    type=int, default=260)
    p.add_argument("--github-token",  type=str, default=None)
    p.add_argument("--skip-prepare",  action="store_true")
    args = p.parse_args()

    configure_logging()
    labels = build(args.raw_dir, args.max_malicious, args.max_benign, args.github_token)

    if not args.skip_prepare:
        from lamps.data.prepare_d2 import prepare
        prepare(raw_dir=args.raw_dir)

    m = sum(1 for v in labels.values() if v == 1)
    b = sum(1 for v in labels.values() if v == 0)
    logger.info("Done: %d mal + %d ben = %d packages", m, b, len(labels))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
