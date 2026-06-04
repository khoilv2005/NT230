"""LAMPS full-pipeline web demo.

Run from the repository root:

    uvicorn web_demo.app:app --host 127.0.0.1 --port 8000
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from lamps.config import CODEBERT_BEST_CKPT
from hybrid_pypi_classifier import build_pipeline


STATIC_DIR = Path(__file__).resolve().parent / "static"
ROOT_MODEL_CKPT = REPO_ROOT / "model.bin"

app = FastAPI(
    title="LAMPS Full Pipeline Demo",
    description="CrewAI-style full pipeline demo for malicious PyPI package detection.",
    version="1.0.0",
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

_pipeline_cache: dict[tuple[str, bool, str, str], Any] = {}
_pipeline_lock = asyncio.Lock()


class AnalyzeRequest(BaseModel):
    package: str = Field(..., min_length=1, max_length=214, description="PyPI package name")
    version: str | None = Field(default=None, max_length=128, description="Optional package version")
    use_crewai: bool = Field(default=True, description="Run CrewAI-backed paper pipeline")
    explain: bool = Field(default=True, description="Use Ollama Cloud for extractor/verdict reasoning")
    checkpoint: str | None = Field(default=None, description="Optional CodeBERT model.bin path")
    ollama_model: str | None = Field(default=None, description="Ollama model name")
    ollama_host: str | None = Field(default=None, description="Ollama host")


def _clean_package(name: str) -> str:
    package = name.strip()
    if not package:
        raise HTTPException(status_code=400, detail="Package name is required.")
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    if any(ch not in allowed for ch in package):
        raise HTTPException(
            status_code=400,
            detail="Package name may contain only letters, numbers, dot, underscore, and hyphen.",
        )
    return package


def _resolve_checkpoint(value: str | None) -> Path:
    if value:
        checkpoint = Path(value).expanduser()
    elif ROOT_MODEL_CKPT.exists():
        checkpoint = ROOT_MODEL_CKPT
    else:
        checkpoint = CODEBERT_BEST_CKPT
    if not checkpoint.is_absolute():
        checkpoint = (REPO_ROOT / checkpoint).resolve()
    if not checkpoint.exists():
        raise HTTPException(status_code=400, detail=f"Missing CodeBERT checkpoint: {checkpoint}")
    return checkpoint


async def _get_pipeline(request: AnalyzeRequest):
    checkpoint = _resolve_checkpoint(request.checkpoint)
    ollama_model = request.ollama_model or os.getenv("OLLAMA_MODEL", "deepseek-v4-flash:cloud")
    ollama_host = request.ollama_host or os.getenv("OLLAMA_HOST", "https://ollama.com")
    cache_key = (str(checkpoint), request.use_crewai, ollama_model, ollama_host)
    async with _pipeline_lock:
        if cache_key not in _pipeline_cache:
            _pipeline_cache[cache_key] = build_pipeline(
                checkpoint=checkpoint,
                explain=request.explain,
                use_crewai=request.use_crewai,
                ollama_model=ollama_model,
                ollama_host=ollama_host,
            )
        return _pipeline_cache[cache_key]


def _crew_steps(pipeline: Any) -> list[dict[str, Any]]:
    execution = getattr(pipeline, "last_execution", None)
    if execution is None:
        return []
    return execution.to_dict().get("steps", [])


def _malicious_files(payload: dict[str, Any]) -> set[str]:
    verdict = payload.get("verdict") or {}
    return {item.get("path", "") for item in verdict.get("malicious_files", [])}


def _shape_result(payload: dict[str, Any], pipeline: Any, elapsed_sec: float) -> dict[str, Any]:
    flagged = _malicious_files(payload)
    files = []
    for item in payload.get("files", []):
        path = item.get("path", "")
        files.append(
            {
                "path": path,
                "label": item.get("label", ""),
                "score": item.get("score", 0.0),
                "flagged": path in flagged,
            }
        )
    files.sort(key=lambda x: (not x["flagged"], -float(x.get("score") or 0), x["path"]))
    payload["files"] = files
    payload["crew_execution"] = _crew_steps(pipeline)
    payload["elapsed_sec"] = round(elapsed_sec, 2)
    return payload


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "repo_root": str(REPO_ROOT),
        "default_checkpoint": str(_resolve_checkpoint(None)),
        "checkpoint_exists": _resolve_checkpoint(None).exists(),
        "ollama_key": "set" if os.getenv("OLLAMA_API_KEY") else "missing",
    }


@app.post("/api/analyze")
async def analyze(request: AnalyzeRequest) -> dict[str, Any]:
    package = _clean_package(request.package)
    version = (request.version or "").strip() or None
    pipeline = await _get_pipeline(request)
    started = time.perf_counter()
    try:
        result = await asyncio.to_thread(pipeline.analyze_package, package, version)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=repr(exc)) from exc
    elapsed = time.perf_counter() - started
    return _shape_result(result.to_dict(), pipeline, elapsed)
