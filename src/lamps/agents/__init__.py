"""Role-specialised agents that compose the LAMPS pipeline (paper §3.1)."""

from .fetcher import FetcherAgent
from .extractor import ExtractorAgent, LLMArchiveExtractorAgent, LLMExtractorAgent
from .classifier import ClassifierAgent
from .verdict import VerdictAgent
from .risk_calibrated_verdict import RiskCalibratedVerdictAgent
from .planner import SupervisorPlannerAgent
from .package_acquisition import PackageAcquisitionAgent
from .context_graph import StaticContextGraphAgent
from .critic_verifier import CriticVerifierAgent
from .decision_audit import DecisionAuditAgent

__all__ = [
    "FetcherAgent",
    "ExtractorAgent",
    "LLMArchiveExtractorAgent",
    "LLMExtractorAgent",
    "ClassifierAgent",
    "VerdictAgent",
    "RiskCalibratedVerdictAgent",
    "SupervisorPlannerAgent",
    "PackageAcquisitionAgent",
    "StaticContextGraphAgent",
    "CriticVerifierAgent",
    "DecisionAuditAgent",
]
