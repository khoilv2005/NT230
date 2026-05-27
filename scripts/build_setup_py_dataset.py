from __future__ import annotations

import csv
import hashlib
import io
import json
import shutil
import subprocess
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path


BASE = Path(r"D:\lamps-jss\data")
OUT = BASE / "setup_py_dataset"
MANIFEST = OUT / "manifest.csv"
SUMMARY = OUT / "summary.json"


@dataclass(frozen=True)
class ArchiveSample:
    dataset: str
    label: str
    rel_path: str
    disk_path: Path | None = None
    git_root: Path | None = None


def clean_output() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    (OUT / "malicious").mkdir(parents=True)
    (OUT / "benign").mkdir(parents=True)


def safe_id(dataset: str, rel_path: str) -> str:
    digest = hashlib.sha1(f"{dataset}/{rel_path}".encode("utf-8", "surrogateescape")).hexdigest()[:12]
    parts = rel_path.replace("\\", "/").split("/")
    stem = "__".join(parts[:-1] + [Path(parts[-1]).name])
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in stem)
    safe = safe.strip("._-")[:130]
    return f"{dataset}__{safe}__{digest}"


def datadog_samples() -> list[ArchiveSample]:
    root = BASE / "extracted_counts" / "datadog-pypi-tree" / "samples" / "pypi"
    samples: list[ArchiveSample] = []
    if not root.exists():
        return samples
    for archive in root.rglob("*.zip"):
        rel = archive.relative_to(root).as_posix()
        label = rel.split("/", 1)[0]
        samples.append(ArchiveSample("datadog_pypi", "malicious", rel, archive, None))
    return samples


def git_files(root: Path) -> list[str]:
    proc = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    raw = proc.stdout.decode("utf-8", "surrogateescape")
    return [item for item in raw.split("\0") if item]


def pypi_malregistry_samples() -> list[ArchiveSample]:
    root = BASE / "pypi_malregistry"
    samples: list[ArchiveSample] = []
    if not root.exists():
        return samples
    for rel in git_files(root):
        lower = rel.lower()
        if lower.endswith((".tar.gz", ".tgz", ".zip", ".whl")):
            samples.append(ArchiveSample("pypi_malregistry", "malicious", rel, root / rel, root))
    return samples


def read_archive_bytes(sample: ArchiveSample) -> bytes | None:
    if sample.disk_path and sample.disk_path.exists():
        try:
            return sample.disk_path.read_bytes()
        except OSError:
            pass
    if sample.git_root:
        proc = subprocess.run(
            ["git", "-C", str(sample.git_root), "show", f"HEAD:{sample.rel_path}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if proc.returncode == 0:
            return proc.stdout
    return None


def extract_setup_from_zip(data: bytes) -> tuple[str, bytes] | None:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        names = [
            name
            for name in zf.namelist()
            if not name.endswith("/") and Path(name).name == "setup.py" and "__MACOSX/" not in name
        ]
        if not names:
            return None
        names.sort(key=lambda n: (n.count("/"), len(n), n))
        name = names[0]
        try:
            return name, zf.read(name)
        except RuntimeError as exc:
            if "password required" not in str(exc).lower() and "encrypted" not in str(exc).lower():
                raise
            return name, zf.read(name, pwd=b"infected")


def extract_setup_from_tar(data: bytes) -> tuple[str, bytes] | None:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        members = [
            member
            for member in tf.getmembers()
            if member.isfile() and Path(member.name).name == "setup.py"
        ]
        if not members:
            return None
        members.sort(key=lambda m: (m.name.count("/"), len(m.name), m.name))
        member = members[0]
        extracted = tf.extractfile(member)
        if extracted is None:
            return None
        return member.name, extracted.read()


def extract_setup(sample: ArchiveSample) -> tuple[str, bytes] | None:
    data = read_archive_bytes(sample)
    if data is None:
        return None
    if data.startswith(b"PK\x03\x04"):
        return extract_setup_from_zip(data)
    lower = sample.rel_path.lower()
    if lower.endswith((".zip", ".whl")):
        return extract_setup_from_zip(data)
    if lower.endswith((".tar.gz", ".tgz", ".tar")):
        return extract_setup_from_tar(data)
    return None


def main() -> None:
    clean_output()
    samples = datadog_samples() + pypi_malregistry_samples()
    rows: list[dict[str, str]] = []
    errors: list[dict[str, str]] = []
    counts = {
        "input_archives": len(samples),
        "written": {"malicious": 0, "benign": 0},
        "skipped_no_setup_py": 0,
        "errors": 0,
        "by_dataset": {},
    }

    for sample in samples:
        counts["by_dataset"].setdefault(sample.dataset, {"input": 0, "written": 0, "skipped": 0, "errors": 0})
        counts["by_dataset"][sample.dataset]["input"] += 1
        try:
            found = extract_setup(sample)
            if found is None:
                counts["skipped_no_setup_py"] += 1
                counts["by_dataset"][sample.dataset]["skipped"] += 1
                continue
            setup_member, setup_bytes = found
            sample_id = safe_id(sample.dataset, sample.rel_path)
            dst_dir = OUT / sample.label / sample_id
            dst_dir.mkdir(parents=True, exist_ok=False)
            (dst_dir / "setup.py").write_bytes(setup_bytes)
            counts["written"][sample.label] += 1
            counts["by_dataset"][sample.dataset]["written"] += 1
            rows.append(
                {
                    "sample_id": sample_id,
                    "label": sample.label,
                    "dataset": sample.dataset,
                    "source_archive": sample.rel_path,
                    "setup_member": setup_member,
                    "output": str(dst_dir / "setup.py"),
                }
            )
        except Exception as exc:  # noqa: BLE001
            counts["errors"] += 1
            counts["by_dataset"][sample.dataset]["errors"] += 1
            errors.append({"dataset": sample.dataset, "source_archive": sample.rel_path, "error": repr(exc)})

    with MANIFEST.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["sample_id", "label", "dataset", "source_archive", "setup_member", "output"],
        )
        writer.writeheader()
        writer.writerows(rows)
    SUMMARY.write_text(json.dumps(counts, indent=2), encoding="utf-8")
    (OUT / "errors.json").write_text(json.dumps(errors, indent=2), encoding="utf-8")
    print(json.dumps(counts, indent=2))


if __name__ == "__main__":
    main()
