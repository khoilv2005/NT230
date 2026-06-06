"""Static Context Graph Agent for TRACE-LAMPS."""

from __future__ import annotations

import ast
import re
from pathlib import PurePosixPath
from typing import Any, Iterable

from lamps.agents.extractor import ExtractedFile


class StaticContextGraphAgent:
    """Extract AST, regex, path, and import evidence without executing code."""

    def analyze(self, files: Iterable[ExtractedFile]) -> dict[str, dict[str, Any]]:
        files = list(files)
        source_by_path = {f.rel_path: f.source for f in files}
        imported_by_entrypoint = self._entrypoint_import_targets(source_by_path)
        context = {}
        for file in files:
            context[file.rel_path] = self._file_context(
                file.rel_path, file.source, imported_by_entrypoint
            )
        return context

    def _file_context(
        self,
        rel_path: str,
        source: str,
        imported_by_entrypoint: set[str],
    ) -> dict[str, Any]:
        imports = self._imports(source)
        suspicious = self._suspicious_indicators(source)
        benign = self._benign_indicators(rel_path)
        is_critical = self._is_critical_path(rel_path, source)
        return {
            "path": rel_path,
            "is_critical": is_critical,
            "is_entrypoint": self._is_entrypoint_path(rel_path, source),
            "imported_by_entrypoint": rel_path in imported_by_entrypoint,
            "imports": sorted(imports),
            "suspicious_indicators": suspicious,
            "benign_indicators": benign,
            "is_generated_or_resource": "generated_resource" in benign,
            "has_behavior_evidence": bool(suspicious),
        }

    def _suspicious_indicators(self, source: str) -> list[str]:
        text = source.lower()
        checks = [
            ("exec", r"\bexec\s*\("),
            ("eval", r"\beval\s*\("),
            ("compile", r"\bcompile\s*\("),
            ("base64_decode", r"(base64|b64decode)"),
            ("subprocess", r"subprocess\.(popen|call|run)\s*\("),
            ("os_system", r"os\.(system|popen)\s*\("),
            ("network", r"(requests|urllib\.request)\.(get|post|urlopen)\s*\("),
            ("socket", r"\bsocket\."),
            ("credential_terms", r"(token|password|secret|api_key|webhook)"),
        ]
        return [name for name, pattern in checks if re.search(pattern, text)]

    def _benign_indicators(self, rel_path: str) -> list[str]:
        lowered = rel_path.lower().replace("\\", "/")
        path = PurePosixPath(lowered)
        parts = set(path.parts)
        indicators = []
        if parts & {"docs", "doc", "examples", "example", "tutorial", "tutorials"}:
            indicators.append("docs_examples")
        if parts & {"tests", "test", "testing", "benchmarks", "benchmark"}:
            indicators.append("tests_benchmarks")
        if parts & {"tools", "scripts", "dev", "demo", "demos", "samples", "sample"}:
            indicators.append("development_tooling")
        if path.name.startswith("test_") or path.name.endswith("_test.py"):
            indicators.append("test_file")
        generated_markers = [
            "generated",
            "fixtures",
            "resources/",
            "parser/resources",
            "tables/",
            "_version",
            "coefficients.py",
        ]
        if any(marker in lowered for marker in generated_markers):
            indicators.append("generated_resource")
        return indicators

    def _entrypoint_import_targets(self, source_by_path: dict[str, str]) -> set[str]:
        module_to_path = self._module_index(source_by_path)
        targets: set[str] = set()
        for rel_path, source in source_by_path.items():
            if not self._is_entrypoint_path(rel_path, source):
                continue
            imports = self._imports(source)
            for module in imports:
                for candidate in self._module_candidates(module):
                    path = module_to_path.get(candidate)
                    if path and path != rel_path:
                        targets.add(path)
        return targets

    def _module_index(self, source_by_path: dict[str, str]) -> dict[str, str]:
        index = {}
        for rel_path in source_by_path:
            path = PurePosixPath(rel_path.replace("\\", "/"))
            if path.suffix != ".py":
                continue
            parts = list(path.with_suffix("").parts)
            if parts and parts[-1] == "__init__":
                parts = parts[:-1]
            for start in range(len(parts)):
                module = ".".join(parts[start:])
                if module:
                    index.setdefault(module, rel_path)
        return index

    def _imports(self, source: str) -> set[str]:
        imports: set[str] = set()
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return imports
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module)
                imports.update(f"{node.module}.{alias.name}" for alias in node.names)
        return imports

    def _module_candidates(self, module: str) -> list[str]:
        parts = module.split(".")
        return [".".join(parts[i:]) for i in range(len(parts))]

    def _is_critical_path(self, rel_path: str, source: str) -> bool:
        path = PurePosixPath(rel_path.replace("\\", "/"))
        name = path.name.lower()
        lowered = rel_path.lower().replace("\\", "/")
        if name in {
            "setup.py",
            "__main__.py",
            "install.py",
            "installer.py",
            "post_install.py",
            "build.py",
        }:
            return True
        if name == "__init__.py":
            return True
        if "cmdclass" in source and ("install" in source or "develop" in source):
            return True
        return "/setup/" in lowered or "/install/" in lowered

    def _is_entrypoint_path(self, rel_path: str, source: str) -> bool:
        path = PurePosixPath(rel_path.replace("\\", "/"))
        name = path.name.lower()
        lowered = rel_path.lower().replace("\\", "/")
        if name in {
            "setup.py",
            "__main__.py",
            "install.py",
            "installer.py",
            "post_install.py",
            "build.py",
        }:
            return True
        if "cmdclass" in source and ("install" in source or "develop" in source):
            return True
        return "/setup/" in lowered or "/install/" in lowered
