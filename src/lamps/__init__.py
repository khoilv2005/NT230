"""LAMPS - LLM-based multi-Agent system for detecting Malicious PyPI PackageS.

Reference: Zeshan et al., "Many hands make light work: An LLM-based multi-agent
system for detecting malicious PyPI packages", JSS 2026.
"""

from .trace_pipeline import TraceLampsPipeline, TraceLampsResult

__version__ = "1.0.0"

__all__ = ["TraceLampsPipeline", "TraceLampsResult"]
