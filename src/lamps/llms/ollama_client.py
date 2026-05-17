"""Ollama LLM client wrapper dùng cho các reasoning agents trong LAMPS."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


DEFAULT_MODEL = os.getenv("OLLAMA_MODEL", "deepseek-v4-flash:cloud")


def _load_env() -> None:
    """Load .env file (supports both standard and PowerShell format)."""
    env_file = Path(__file__).resolve().parents[3] / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # PowerShell: $env:KEY = "value"
        m = re.match(r'^\$env:(\w+)\s*=\s*["\']?([^"\']+)["\']?', line)
        if m:
            os.environ.setdefault(m.group(1), m.group(2).strip())
            continue
        # Standard: KEY=value
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
    """Thin wrapper quanh ollama.chat — cùng interface với GeminiClient."""

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        api_key: Optional[str] = None,
        host: Optional[str] = None,
    ) -> None:
        try:
            import ollama as _ollama
            self._ollama = _ollama
        except ImportError as exc:
            raise ImportError("Cần cài ollama: pip install ollama") from exc

        self.model = model
        # API key cho Ollama cloud services
        self._api_key = api_key or os.getenv("OLLAMA_API_KEY")
        self._host = host or os.getenv("OLLAMA_HOST")

    def _get_client(self):
        """Trả về ollama.Client với host/key nếu có."""
        kwargs = {}
        if self._host:
            kwargs["host"] = self._host
        if self._api_key:
            kwargs["headers"] = {"Authorization": f"Bearer {self._api_key}"}
        if kwargs:
            return self._ollama.Client(**kwargs)
        return None  # dùng default client

    def generate(self, prompt: str, system: Optional[str] = None) -> OllamaResponse:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        client = self._get_client()
        if client:
            response = client.chat(model=self.model, messages=messages)
        else:
            response = self._ollama.chat(model=self.model, messages=messages)

        text = response.message.content or ""
        usage = getattr(response, "usage", None)
        return OllamaResponse(
            text=text.strip(),
            prompt_tokens=getattr(usage, "prompt_tokens", 0) or 0,
            completion_tokens=getattr(usage, "completion_tokens", 0) or 0,
        )

    def __call__(self, prompt: str) -> str:
        return self.generate(prompt).text

    def run(self, prompt: str) -> str:
        return self.generate(prompt).text
