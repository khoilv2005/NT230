"""Editable-install entry point so `from lamps...` works after `pip install -e .`."""

from setuptools import find_packages, setup


setup(
    name="lamps",
    version="1.0.0",
    description="LAMPS — LLM-based multi-agent system for detecting malicious PyPI packages",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.10",
)
