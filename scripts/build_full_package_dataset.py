from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path
import re

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

DATA_ROOT = Path(r"D:\lamps-jss\data")
DEFAULT_D2_RAW = REPO_ROOT / "data" / "d2" / "raw"
DEFAULT_SETUP_MANIFEST = DATA_ROOT / "setup_py_dataset" / "manifest.csv"
DEFAULT_OUT = DATA_ROOT / "full_package_dataset"
DATADOG_ARCHIVE_ROOT = (
    DATA_ROOT / "extracted_counts" / "datadog-pypi-tree" / "samples" / "pypi"
)
PYPI_MALREGISTRY_ROOT = DATA_ROOT / "pypi_malregistry"
ZIP_PASSWORD = b"infected"
USER_AGENT = "lamps-jss-full-package-builder/1.0"


def safe_id(prefix: str, raw: str) -> str:
    digest = hashlib.sha1(f"{prefix}/{raw}".encode("utf-8", "surrogateescape")).hexdigest()[:12]
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in raw.replace("\\", "/"))
    safe = safe.strip("._-")[:140]
    return f"{prefix}__{safe}__{digest}"


def package_folder_name(name: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in name)
    return safe.strip("._-") or "package"

def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower().strip()


def strip_archive_suffix(filename: str) -> str:
    lower = filename.lower()
    for suffix in (".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip", ".whl", ".tar"):
        if lower.endswith(suffix):
            return filename[: -len(suffix)]
    return Path(filename).stem


def split_name_version_from_filename(filename: str) -> tuple[str, str]:
    stem = strip_archive_suffix(Path(filename).name)
    match = re.match(r"^(.+)-([0-9][A-Za-z0-9_.!+~-]*)$", stem)
    if match:
        return match.group(1), match.group(2)
    return stem, ""


def archive_identity(dataset: str, source: str, sample_id: str = "") -> tuple[str, str]:
    source_norm = source.replace("\\", "/")
    parts = [p for p in source_norm.split("/") if p]
    if dataset == "datadog_pypi" and len(parts) >= 4:
        return parts[1], parts[2]
    if dataset == "datadog_pypi" and len(parts) >= 3:
        name = parts[1]
        filename = parts[-1]
        version_match = re.search(r"-v([0-9][A-Za-z0-9_.!+~-]*)", filename)
        return name, version_match.group(1) if version_match else ""
    if dataset == "pypi_malregistry" and len(parts) >= 3:
        return parts[0], parts[1]
    if source_norm.startswith(("http://", "https://")):
        return split_name_version_from_filename(source_norm.split("?", 1)[0].rsplit("/", 1)[-1])
    if sample_id:
        item = sample_id
        for prefix in ("top_pypi__top_pypi_", "pypi_simple__top_pypi_"):
            if item.startswith(prefix):
                item = item[len(prefix):]
                break
        match = re.match(r"^(.+)_([0-9][A-Za-z0-9_.!+~-]*)_", item)
        if match:
            return match.group(1), match.group(2)
    if parts:
        return split_name_version_from_filename(parts[-1])
    return sample_id or "unknown", ""


def infer_d2_identity(package: str, src_dir: Path) -> tuple[str, str]:
    package_name = package[:-4] if package.endswith("-mal") else package
    normalized_package = normalize_name(package_name)

    best_version = ""
    for path in sorted(src_dir.rglob("*")):
        parts = path.relative_to(src_dir).parts
        for part in parts:
            date_match = re.search(r"-v([0-9][A-Za-z0-9_.!+~-]*)$", part)
            if date_match:
                return package_name, date_match.group(1)

            stem = strip_archive_suffix(part)
            pair_match = re.match(r"^(.+?)[-_]([0-9][A-Za-z0-9_.!+~-]*)$", stem)
            if not pair_match:
                continue
            name, version = pair_match.group(1), pair_match.group(2)
            if normalize_name(name) == normalized_package:
                return package_name, version
            if not best_version:
                best_version = version

    for setup_py in sorted(src_dir.rglob("setup.py")):
        try:
            source = setup_py.read_text(encoding="utf-8", errors="ignore")[:20000]
        except OSError:
            continue
        version_match = re.search(
            r"\bversion\s*=\s*['\"]([0-9][A-Za-z0-9_.!+~-]*)['\"]",
            source,
        )
        if version_match:
            return package_name, version_match.group(1)

    return package_name, best_version

def unique_key(name: str, version: str) -> str:
    return f"{normalize_name(name)}=={version.strip().lower()}"


def clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def load_d2_labels(raw_dir: Path) -> dict[str, int]:
    labels_path = raw_dir / "labels.csv"
    if not labels_path.exists():
        return {}
    with labels_path.open(newline="", encoding="utf-8") as f:
        return {row["package"]: int(row["label"]) for row in csv.DictReader(f)}


def copy_py_tree(src_dir: Path, dst_dir: Path) -> int:
    count = 0
    for src in sorted(src_dir.rglob("*.py")):
        if not src.is_file():
            continue
        rel = src.relative_to(src_dir)
        dst = dst_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        count += 1
    return count


def git_show(root: Path, rel_path: str) -> bytes | None:
    proc = subprocess.run(
        ["git", "-C", str(root), "show", f"HEAD:{rel_path}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return proc.stdout if proc.returncode == 0 else None


def read_archive(row: dict[str, str]) -> tuple[str, bytes] | None:
    dataset = row.get("dataset", "")
    source = row.get("source_archive", "")
    if not source:
        return None

    if source.startswith(("http://", "https://")):
        req = urllib.request.Request(source, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=90) as resp:
            return Path(source.split("?", 1)[0]).name, resp.read()

    if dataset == "datadog_pypi":
        path = DATADOG_ARCHIVE_ROOT / source
        if path.exists():
            return path.name, path.read_bytes()
        return None

    if dataset == "pypi_malregistry":
        path = PYPI_MALREGISTRY_ROOT / source
        if path.exists():
            return path.name, path.read_bytes()
        data = git_show(PYPI_MALREGISTRY_ROOT, source)
        return (Path(source).name, data) if data is not None else None

    return None


def safe_members(members: list[str]) -> list[str]:
    out: list[str] = []
    for name in members:
        normal = Path(name.replace("\\", "/"))
        if normal.is_absolute() or ".." in normal.parts:
            continue
        out.append(name)
    return out


def extract_zip_bytes(data: bytes, dest: Path) -> bool:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = safe_members(zf.namelist())
            for name in names:
                try:
                    zf.extract(name, path=dest)
                except RuntimeError as exc:
                    if "password" not in str(exc).lower() and "encrypted" not in str(exc).lower():
                        raise
                    zf.extract(name, path=dest, pwd=ZIP_PASSWORD)
        return True
    except (zipfile.BadZipFile, RuntimeError, OSError):
        return False


def extract_tar_bytes(data: bytes, dest: Path) -> bool:
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
            members = []
            for member in tf.getmembers():
                normal = Path(member.name.replace("\\", "/"))
                if normal.is_absolute() or ".." in normal.parts:
                    continue
                members.append(member)
            tf.extractall(path=dest, members=members)
        return True
    except (tarfile.TarError, OSError):
        return False


def unpack_archive_bytes(filename: str, data: bytes, dest: Path) -> bool:
    lower = filename.lower()
    if data.startswith(b"PK\x03\x04") or lower.endswith((".zip", ".whl")):
        return extract_zip_bytes(data, dest)
    if lower.endswith((".tar.gz", ".tgz", ".tar", ".tar.bz2", ".tar.xz")):
        return extract_tar_bytes(data, dest)
    return False


def unpack_nested_archives(root: Path, max_rounds: int = 3) -> None:
    seen: set[Path] = set()
    archive_suffixes = (".zip", ".whl", ".tar", ".tgz", ".gz", ".bz2", ".xz")
    for _ in range(max_rounds):
        extracted_any = False
        for archive in sorted(root.rglob("*")):
            if archive in seen or not archive.is_file():
                continue
            lower = archive.name.lower()
            if not lower.endswith(archive_suffixes):
                continue
            if not any(
                lower.endswith(s)
                for s in (".zip", ".whl", ".tar.gz", ".tgz", ".tar", ".tar.bz2", ".tar.xz")
            ):
                continue
            seen.add(archive)
            dest = archive.with_suffix(archive.suffix + ".extracted")
            dest.mkdir(parents=True, exist_ok=True)
            try:
                data = archive.read_bytes()
            except OSError:
                continue
            if unpack_archive_bytes(archive.name, data, dest):
                extracted_any = True
        if not extracted_any:
            break


def extract_package_py_files(filename: str, data: bytes, dst_dir: Path) -> int:
    with tempfile.TemporaryDirectory(prefix="lamps_fullpkg_") as tmp_name:
        tmp = Path(tmp_name)
        if not unpack_archive_bytes(filename, data, tmp):
            return 0
        unpack_nested_archives(tmp)
        return copy_py_tree(tmp, dst_dir)


def successful_count(rows: list[dict[str, str]]) -> int:
    return sum(1 for row in rows if int(row.get("n_py_files", "0")) > 0)

def successful_label_counts(rows: list[dict[str, str]]) -> dict[str, int]:
    counts = {"0": 0, "1": 0}
    for row in rows:
        if int(row.get("n_py_files", "0")) > 0:
            counts[row["label"]] += 1
    return counts

def target_reached(
    rows: list[dict[str, str]],
    target_total: int | None,
    target_labels: dict[str, int] | None,
) -> bool:
    if target_labels:
        counts = successful_label_counts(rows)
        return all(counts[label] >= target for label, target in target_labels.items())
    return target_total is not None and successful_count(rows) >= target_total


def materialize_d2(
    raw_dir: Path,
    out_raw: Path,
    rows: list[dict[str, str]],
    seen_keys: set[str],
    seen_names: set[str],
    target_total: int | None,
    target_labels: dict[str, int] | None,
) -> dict[str, int]:
    labels = load_d2_labels(raw_dir)
    count = {
        "packages": 0,
        "files": 0,
        "duplicates": 0,
        "duplicate_names": 0,
        "missing_version": 0,
    }
    for package, label in sorted(labels.items()):
        if target_reached(rows, target_total, target_labels):
            break
        label_str = str(label)
        if target_labels and successful_label_counts(rows)[label_str] >= target_labels[label_str]:
            continue
        src = raw_dir / package
        if not src.is_dir():
            continue
        package_name, package_version = infer_d2_identity(package, src)
        if not package_version:
            count["missing_version"] += 1
            continue
        name_key = normalize_name(package_name)
        key = unique_key(package_name, package_version)
        if key in seen_keys:
            count["duplicates"] += 1
            continue
        if name_key in seen_names:
            count["duplicate_names"] += 1
            continue
        dst_name = package_folder_name(package_name)
        dst = out_raw / dst_name
        n_py = copy_py_tree(src, dst)
        if n_py == 0:
            shutil.rmtree(dst, ignore_errors=True)
            continue
        seen_keys.add(key)
        seen_names.add(name_key)
        rows.append(
            {
                "package": dst_name,
                "package_name": package_name,
                "package_version": package_version,
                "unique_key": key,
                "label": label_str,
                "source_dataset": "d2",
                "source_archive": package,
                "n_py_files": str(n_py),
                "output_dir": str(dst),
            }
        )
        count["packages"] += 1
        count["files"] += n_py
    return count


def materialize_setup_manifest(
    manifest_path: Path,
    out_raw: Path,
    rows: list[dict[str, str]],
    seen_keys: set[str],
    seen_names: set[str],
    max_rows: int | None,
    target_total: int | None,
    target_labels: dict[str, int] | None,
) -> dict[str, int]:
    count = {"packages": 0, "files": 0, "skipped": 0, "duplicates": 0, "duplicate_names": 0, "errors": 0}
    with manifest_path.open(newline="", encoding="utf-8") as f:
        manifest_rows = list(csv.DictReader(f))
    if max_rows is not None:
        manifest_rows = manifest_rows[:max_rows]

    for row in manifest_rows:
        if target_reached(rows, target_total, target_labels):
            break
        label_name = row.get("label", "")
        label = "1" if label_name == "malicious" else "0"
        if target_labels and successful_label_counts(rows)[label] >= target_labels[label]:
            continue
        dataset = row.get("dataset", "unknown")
        source = row.get("source_archive", "")
        sample_id = row.get("sample_id") or safe_id(dataset, source)
        package_name, package_version = archive_identity(dataset, source, sample_id)
        name_key = normalize_name(package_name)
        key = unique_key(package_name, package_version)
        if key in seen_keys:
            count["duplicates"] += 1
            continue
        if name_key in seen_names:
            count["duplicate_names"] += 1
            continue
        dst_name = package_folder_name(package_name)
        dst = out_raw / dst_name
        if dst.exists() and any(dst.rglob("*.py")):
            count["skipped"] += 1
            continue
        try:
            archive = read_archive(row)
            if archive is None:
                count["skipped"] += 1
                continue
            filename, data = archive
            dst.mkdir(parents=True, exist_ok=True)
            n_py = extract_package_py_files(filename, data, dst)
            if n_py == 0:
                shutil.rmtree(dst, ignore_errors=True)
                count["skipped"] += 1
                continue
            if not package_version:
                _, inferred_version = infer_d2_identity(package_name, dst)
                if inferred_version:
                    package_version = inferred_version
                    key = unique_key(package_name, package_version)
            seen_keys.add(key)
            seen_names.add(name_key)
            rows.append(
                {
                    "package": dst_name,
                    "package_name": package_name,
                    "package_version": package_version,
                    "unique_key": key,
                    "label": label,
                    "source_dataset": dataset,
                    "source_archive": source,
                    "n_py_files": str(n_py),
                    "output_dir": str(dst),
                }
            )
            count["packages"] += 1
            count["files"] += n_py
        except Exception as exc:  # noqa: BLE001
            shutil.rmtree(dst, ignore_errors=True)
            count["errors"] += 1
            rows.append(
                {
                    "package": dst_name,
                    "package_name": package_name,
                    "package_version": package_version,
                    "unique_key": key,
                    "label": label,
                    "source_dataset": dataset,
                    "source_archive": source,
                    "n_py_files": "0",
                    "output_dir": str(dst),
                    "error": repr(exc),
                }
            )
    return count


def write_labels(out_raw: Path, rows: list[dict[str, str]]) -> None:
    with (out_raw / "labels.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["package", "label"])
        for row in rows:
            if int(row.get("n_py_files", "0")) > 0:
                writer.writerow([row["package"], row["label"]])


def write_manifest(out_dir: Path, rows: list[dict[str, str]]) -> None:
    fieldnames = [
        "package",
        "package_name",
        "package_version",
        "unique_key",
        "label",
        "source_dataset",
        "source_archive",
        "n_py_files",
        "output_dir",
        "error",
    ]
    with (out_dir / "manifest.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_markdown(out_dir: Path, rows: list[dict[str, str]]) -> None:
    ok_rows = [row for row in rows if int(row.get("n_py_files", "0")) > 0]
    label_counts = {"0": 0, "1": 0}
    for row in ok_rows:
        label_counts[row["label"]] += 1
    lines = [
        "# Full Package Dataset Package List",
        "",
        f"- Total packages: {len(ok_rows)}",
        f"- Benign packages: {label_counts['0']}",
        f"- Malicious packages: {label_counts['1']}",
        "- Folder rule: raw folder name is package name only; unsafe path characters are replaced with `_`.",
        "- Duplicate rule: normalized package name, plus normalized package name + version.",
        "- Note: D2 raw labels do not include package version metadata; D2 versions are inferred from folder names or setup.py. Packages without inferable version are skipped.",
        "",
        "| # | Label | Package | Version | Source | Python files | Folder |",
        "|---:|---|---|---|---|---:|---|",
    ]
    for idx, row in enumerate(ok_rows, start=1):
        label = "malicious" if row["label"] == "1" else "benign"
        package_name = row.get("package_name") or row["package"]
        version = row.get("package_version") or "unknown"
        source = row.get("source_dataset", "")
        n_py = row.get("n_py_files", "0")
        dataset_id = row["package"]
        lines.append(
            f"| {idx} | {label} | `{package_name}` | `{version}` | "
            f"`{source}` | {n_py} | `{dataset_id}` |"
        )
    (out_dir / "package_list.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a full-package dataset from D2 + setup_py_dataset archives.")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--d2-raw", type=Path, default=DEFAULT_D2_RAW)
    parser.add_argument("--setup-manifest", type=Path, default=DEFAULT_SETUP_MANIFEST)
    parser.add_argument("--skip-d2", action="store_true")
    parser.add_argument("--skip-new", action="store_true")
    parser.add_argument("--max-new", type=int, default=None)
    parser.add_argument("--target-total", type=int, default=None)
    parser.add_argument("--target-benign", type=int, default=None)
    parser.add_argument("--target-malicious", type=int, default=None)
    parser.add_argument("--clean", action="store_true")
    parser.add_argument("--prepare-jsonl", action="store_true")
    args = parser.parse_args()
    if (args.target_benign is None) != (args.target_malicious is None):
        parser.error("--target-benign and --target-malicious must be used together")

    target_labels = None
    if args.target_benign is not None and args.target_malicious is not None:
        target_labels = {"0": args.target_benign, "1": args.target_malicious}

    out_dir = args.out
    out_raw = out_dir / "raw"
    if args.clean:
        clean_dir(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_raw.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, str]] = []
    seen_keys: set[str] = set()
    seen_names: set[str] = set()
    summary: dict[str, object] = {
        "out": str(out_dir),
        "raw": str(out_raw),
        "target_total": args.target_total,
        "target_labels": target_labels,
        "d2": {},
        "new": {},
    }

    if not args.skip_d2:
        summary["d2"] = materialize_d2(
            args.d2_raw,
            out_raw,
            rows,
            seen_keys,
            seen_names,
            args.target_total,
            target_labels,
        )
    if not args.skip_new and not target_reached(rows, args.target_total, target_labels):
        summary["new"] = materialize_setup_manifest(
            args.setup_manifest,
            out_raw,
            rows,
            seen_keys,
            seen_names,
            args.max_new,
            args.target_total,
            target_labels,
        )

    write_labels(out_raw, rows)
    write_manifest(out_dir, rows)
    write_markdown(out_dir, rows)

    labels = {"0": 0, "1": 0}
    files_by_label = {"0": 0, "1": 0}
    for row in rows:
        if int(row.get("n_py_files", "0")) <= 0:
            continue
        label = row["label"]
        labels[label] += 1
        files_by_label[label] += int(row["n_py_files"])
    summary["labels"] = labels
    summary["files_by_label"] = files_by_label
    summary["total_packages"] = labels["0"] + labels["1"]
    summary["total_py_files"] = files_by_label["0"] + files_by_label["1"]
    summary["unique_package_versions"] = len(
        {row["unique_key"] for row in rows if int(row.get("n_py_files", "0")) > 0}
    )
    summary["unique_package_names"] = len(
        {normalize_name(row["package_name"]) for row in rows if int(row.get("n_py_files", "0")) > 0}
    )
    summary["d2_version_note"] = "D2 raw labels do not include package version metadata; versions are inferred from folder names or setup.py. Packages without inferable version are skipped."
    summary["package_list_md"] = str(out_dir / "package_list.md")

    if args.prepare_jsonl:
        from lamps.data.prepare_d2 import prepare

        prepared = prepare(raw_dir=out_raw, output_dir=out_dir)
        summary["prepared"] = {k: str(v) for k, v in prepared.items()}

    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
