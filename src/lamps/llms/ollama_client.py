"""Ollama LLM client wrapper dùng cho các reasoning agents trong LAMPS.

Tài liệu: https://docs.ollama.com/cloud

Cloud API (ollama.com):
    client = Client(
        host="https://ollama.com",
        headers={"Authorization": "Bearer <OLLAMA_API_KEY>"}
    )
    response = client.chat(model, messages=messages, stream=False)
    text = response.message.content
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


DEFAULT_MODEL = os.getenv("OLLAMA_MODEL", "deepseek-v4-flash:cloud")
OLLAMA_CLOUD_HOST = "https://api.ollama.com"


def _load_env() -> None:
    """Load .env (hỗ trợ PowerShell format và standard format)."""
    env_file = Path(__file__).resolve().parents[3] / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r'^\$env:(\w+)\s*=\s*["\']?([^"\']+)["\']?', line)
        if m:
            os.environ.setdefault(m.group(1), m.group(2).strip())
            continue
        if "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_env()


@dataclass
class OllamaResponse:
    text: str
    prompt_tokens: int = 0
    completion_tokens: int = 0


class OllamaClient:
    """Wrapper quanh Ollama Python library — hỗ trợ cả local và cloud API."""

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        api_key: Optional[str] = None,
        host: Optional[str] = None,
        headers: Optional[dict] = None,
    ) -> None:
        try:
            from ollama import Client as _Client
            self._Client = _Client
        except ImportError as exc:
            raise ImportError("Cần cài: pip install ollama") from exc

        self.model = model
        self._api_key = api_key or os.getenv("OLLAMA_API_KEY")
        self._extra_headers = headers or {}

        # Nếu có API key → dùng cloud host
        if self._api_key:
            self._host = host or OLLAMA_CLOUD_HOST
        else:
            self._host = host or os.getenv("OLLAMA_HOST", "http://localhost:11434")

    def _make_client(self):
        """Tạo Ollama Client theo đúng docs cloud API."""
        h = dict(self._extra_headers)
        if self._api_key:
            h.setdefault("Authorization", f"Bearer {self._api_key}")
        kwargs = {"host": self._host}
        if h:
            kwargs["headers"] = h
        return self._Client(**kwargs)

    def generate(self, prompt: str, system: Optional[str] = None) -> OllamaResponse:
        """Gọi chat API, trả về OllamaResponse."""
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        client = self._make_client()
        response = client.chat(model=self.model, messages=messages, stream=False)

        # response.message.content theo Ollama Python library
        text = response.message.content or ""

        return OllamaResponse(text=text.strip())

    def __call__(self, prompt: str) -> str:
        return self.generate(prompt).text

    def run(self, prompt: str) -> str:
        return self.generate(prompt).text
