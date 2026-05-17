"""Lightweight Gemini client used by the LAMPS reasoning agents.

Supports both the Google AI Studio API key path (``GEMINI_API_KEY``) and
Vertex AI authentication via Application Default Credentials.

The original paper uses LLaMA-3 8B Instruct for the Fetcher, Extractor and
Verdict agents. The shipped ``hybrid_pypi_classifier.py`` switched to Gemini
Flash for cost reasons; both back-ends share the same API surface here so
agents can run with either one transparently.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from lamps.config import GEMINI_DEFAULT_MODEL


@dataclass
class GeminiResponse:
    text: str
    prompt_tokens: int = 0
    completion_tokens: int = 0


class GeminiClient:
    """Thin wrapper around `google.genai` with simple retry semantics."""

    def __init__(
        self,
        model: str = GEMINI_DEFAULT_MODEL,
        api_key: Optional[str] = None,
        use_vertex: Optional[bool] = None,
    ) -> None:
        from google import genai
        from google.genai.types import HttpOptions

        self.model = model

        if use_vertex is None:
            use_vertex = os.getenv("GOOGLE_GENAI_USE_VERTEXAI", "").lower() in {
                "1",
                "true",
                "yes",
            }

        if use_vertex:
            project = os.getenv("GOOGLE_CLOUD_PROJECT")
            location = os.getenv("GOOGLE_CLOUD_LOCATION", "global")
            if not project:
                raise RuntimeError(
                    "GOOGLE_CLOUD_PROJECT must be set when using Vertex AI."
                )
            self._client = genai.Client(
                vertexai=True,
                project=project,
                location=location,
                http_options=HttpOptions(api_version="v1"),
            )
        else:
            api_key = (
                api_key
                or os.getenv("GEMINI_API_KEY")
                or os.getenv("GOOGLE_API_KEY")
            )
            if not api_key:
                raise RuntimeError(
                    "Set GEMINI_API_KEY/GOOGLE_API_KEY, or set "
                    "GOOGLE_GENAI_USE_VERTEXAI=True with GOOGLE_CLOUD_PROJECT."
                )
            self._client = genai.Client(api_key=api_key)

    # ------------------------------------------------------------------
    def generate(self, prompt: str, system: Optional[str] = None) -> GeminiResponse:
        """Generate a completion for ``prompt``.

        Returns the raw text together with token usage when available.
        """
        contents = prompt if system is None else f"{system}\n\n{prompt}"
        response = self._client.models.generate_content(
            model=self.model, contents=contents
        )
        usage = getattr(response, "usage_metadata", None)
        return GeminiResponse(
            text=(response.text or "").strip(),
            prompt_tokens=getattr(usage, "prompt_token_count", 0) or 0,
            completion_tokens=getattr(usage, "candidates_token_count", 0) or 0,
        )

    # CrewAI compatibility shim ---------------------------------------------------
    def __call__(self, prompt: str) -> str:  # pragma: no cover - simple shim
        return self.generate(prompt).text

    def run(self, prompt: str) -> str:  # pragma: no cover - simple shim
        return self.generate(prompt).text
