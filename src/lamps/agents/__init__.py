"""Role-specialised agents that compose the LAMPS pipeline (paper §3.1)."""

from .fetcher import FetcherAgent
from .extractor import ExtractorAgent
from .classifier import ClassifierAgent
from .verdict import VerdictAgent

__all__ = [
    "FetcherAgent",
    "ExtractorAgent",
    "ClassifierAgent",
    "VerdictAgent",
]
