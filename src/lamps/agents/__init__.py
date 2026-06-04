"""Role-specialised agents that compose the LAMPS pipeline (paper §3.1)."""

from .fetcher import FetcherAgent
from .extractor import ExtractorAgent, LLMArchiveExtractorAgent, LLMExtractorAgent
from .classifier import ClassifierAgent
from .verdict import VerdictAgent
from .risk_calibrated_verdict import (
    RiskCalibratedVerdictAgent,
    RiskCalibratedVerdictAgentV2,
)

__all__ = [
    "FetcherAgent",
    "ExtractorAgent",
    "LLMArchiveExtractorAgent",
    "LLMExtractorAgent",
    "ClassifierAgent",
    "VerdictAgent",
    "RiskCalibratedVerdictAgent",
    "RiskCalibratedVerdictAgentV2",
]
