"""Risk-calibrated package aggregation for multi-file PyPI packages.

This module keeps the original conservative VerdictAgent intact and adds a
drop-in subclass that calibrates file-level CodeBERT scores with lightweight
static context. It is intended for experiments on multi-file datasets where a
single high-scoring docs/example file can otherwise flip a whole benign package.
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Mapping, Sequence

from lamps.agents.classifier import FileClassification
from lamps.agents.extractor import ExtractedFile
from lamps.agents.verdict import PackageVerdict, VerdictAgent


@dataclass
class CalibratedFileRisk:
    package: str
    rel_path: str
    base_score: float
    calibrated_score: float
    is_critical: bool
    imported_by_critical: bool
    behavior_score: float
    context_penalty: float
    low_confidence_penalty: float
    reasons: list[str] = field(default_factory=list)


class RiskCalibratedVerdictAgent(VerdictAgent):
    """Context-aware VerdictAgent variant for package-level aggregation.

    The base classifier is unchanged. This agent only changes aggregation:
    CodeBERT probabilities are adjusted using static package context, then
    max-pooled into a package verdict.
    """

    def __init__(
        self,
        llm: object | None = None,
        package_threshold: float = 0.72,
        critical_bonus: float = 0.18,
        import_bonus: float = 0.14,
        behavior_bonus: float = 0.16,
        low_confidence_penalty: float = 0.12,
        docs_examples_penalty: float = 0.36,
        tooling_penalty: float = 0.24,
        large_package_penalty: float = 0.06,
    ) -> None:
        super().__init__(llm=llm)
        self.package_threshold = package_threshold
        self.critical_bonus = critical_bonus
        self.import_bonus = import_bonus
        self.behavior_bonus = behavior_bonus
        self.low_confidence_penalty = low_confidence_penalty
        self.docs_examples_penalty = docs_examples_penalty
        self.tooling_penalty = tooling_penalty
        self.large_package_penalty = large_package_penalty
        self.last_file_risks: list[CalibratedFileRisk] = []

    def aggregate(
        self,
        package: str,
        predictions: Sequence[FileClassification],
        files: Sequence[ExtractedFile] | Mapping[str, str] | None = None,
    ) -> PackageVerdict:
        """Aggregate file predictions with risk calibration.

        ``files`` can be the ExtractedFile list used by ClassifierAgent or a
        mapping from rel_path to source code. Passing sources enables AST-based
        import and behavior checks; without it the agent falls back to path and
        score calibration only.
        """
        source_by_path = self._source_map(files)
        imported_by_critical = self._critical_import_targets(source_by_path)
        n_files = len(predictions)

        risks = [
            self._calibrate_file(pred, source_by_path, imported_by_critical, n_files)
            for pred in predictions
        ]
        self.last_file_risks = risks

        risk_by_path = {r.rel_path: r for r in risks}
        suspicious = [
            p
            for p in predictions
            if risk_by_path.get(p.rel_path, self._empty_risk(p)).calibrated_score
            >= self.package_threshold
        ]
        benign = [p for p in predictions if p not in suspicious]

        if suspicious:
            verdict = PackageVerdict(
                package=package,
                label="malicious",
                target=1,
                malicious_files=list(suspicious),
                benign_files=benign,
            )
        else:
            verdict = PackageVerdict(
                package=package,
                label="benign",
                target=0,
                malicious_files=[],
                benign_files=list(predictions),
            )

        verdict.rationale = self._risk_rationale(verdict, risks)
        return verdict

    def risk_rows(self) -> list[dict]:
        """Return risk details for the last aggregate call."""
        return [
            {
                "package": r.package,
                "path": r.rel_path,
                "base_score": r.base_score,
                "calibrated_score": r.calibrated_score,
                "is_critical": r.is_critical,
                "imported_by_critical": r.imported_by_critical,
                "behavior_score": r.behavior_score,
                "context_penalty": r.context_penalty,
                "low_confidence_penalty": r.low_confidence_penalty,
                "reasons": "; ".join(r.reasons),
            }
            for r in self.last_file_risks
        ]

    def _source_map(
        self, files: Sequence[ExtractedFile] | Mapping[str, str] | None
    ) -> dict[str, str]:
        if files is None:
            return {}
        if isinstance(files, Mapping):
            return {str(k): str(v) for k, v in files.items()}
        return {f.rel_path: f.source for f in files}

    def _calibrate_file(
        self,
        pred: FileClassification,
        source_by_path: Mapping[str, str],
        imported_by_critical: set[str],
        n_files: int,
    ) -> CalibratedFileRisk:
        rel_path = pred.rel_path
        source = source_by_path.get(rel_path, "")
        is_critical = self._is_critical_path(rel_path, source)
        is_imported = rel_path in imported_by_critical
        behavior = self._behavior_score(source)
        context_penalty, context_reasons = self._context_penalty(rel_path, is_critical, is_imported)
        low_penalty = (
            self.low_confidence_penalty
            if 0.50 <= pred.score < 0.80 and not is_critical and not is_imported
            else 0.0
        )
        large_penalty = (
            self.large_package_penalty
            if n_files >= 50 and not is_critical and not is_imported
            else 0.0
        )

        score = pred.score
        reasons: list[str] = []
        if is_critical:
            score += self.critical_bonus
            reasons.append("critical_path")
        if is_imported:
            score += self.import_bonus
            reasons.append("imported_by_critical")
        if behavior > 0:
            score += self.behavior_bonus * behavior
            reasons.append(f"behavior={behavior:.2f}")
        if low_penalty:
            score -= low_penalty
            reasons.append("low_confidence_penalty")
        if context_penalty:
            score -= context_penalty
            reasons.extend(context_reasons)
        if large_penalty:
            score -= large_penalty
            reasons.append("large_package_noncritical_penalty")

        return CalibratedFileRisk(
            package=pred.package,
            rel_path=rel_path,
            base_score=float(pred.score),
            calibrated_score=max(0.0, min(1.0, float(score))),
            is_critical=is_critical,
            imported_by_critical=is_imported,
            behavior_score=behavior,
            context_penalty=context_penalty + large_penalty,
            low_confidence_penalty=low_penalty,
            reasons=reasons,
        )

    def _empty_risk(self, pred: FileClassification) -> CalibratedFileRisk:
        return CalibratedFileRisk(
            package=pred.package,
            rel_path=pred.rel_path,
            base_score=pred.score,
            calibrated_score=pred.score,
            is_critical=False,
            imported_by_critical=False,
            behavior_score=0.0,
            context_penalty=0.0,
            low_confidence_penalty=0.0,
        )

    def _is_critical_path(self, rel_path: str, source: str) -> bool:
        path = PurePosixPath(rel_path.replace("\\", "/"))
        name = path.name.lower()
        lowered = rel_path.lower().replace("\\", "/")
        if name in {"setup.py", "__init__.py", "__main__.py"}:
            return True
        if name in {"install.py", "installer.py", "post_install.py", "build.py"}:
            return True
        if "cmdclass" in source and ("install" in source or "develop" in source):
            return True
        return "/setup/" in lowered or "/install/" in lowered

    def _context_penalty(
        self, rel_path: str, is_critical: bool, imported_by_critical: bool
    ) -> tuple[float, list[str]]:
        if is_critical or imported_by_critical:
            return 0.0, []
        parts = {p.lower() for p in PurePosixPath(rel_path.replace("\\", "/")).parts}
        name = PurePosixPath(rel_path.replace("\\", "/")).name.lower()
        reasons: list[str] = []
        penalty = 0.0
        docs_tokens = {
            "doc",
            "docs",
            "docs_src",
            "examples",
            "example",
            "tutorial",
            "tutorials",
            "benchmarks",
            "benchmark",
            "tests",
            "test",
            "testing",
        }
        tooling_tokens = {
            "scripts",
            "tools",
            "dev",
            "demo",
            "demos",
            "samples",
            "sample",
        }
        if parts & docs_tokens or name.startswith("test_") or name.endswith("_test.py"):
            penalty = max(penalty, self.docs_examples_penalty)
            reasons.append("docs_examples_test_penalty")
        if parts & tooling_tokens:
            penalty = max(penalty, self.tooling_penalty)
            reasons.append("tooling_script_penalty")
        if "health_check" in name or "tutorial" in name:
            penalty = max(penalty, self.tooling_penalty)
            reasons.append("health_tutorial_penalty")
        return penalty, reasons

    def _behavior_score(self, source: str) -> float:
        if not source:
            return 0.0
        text = source.lower()
        score = 0.0

        high_risk_pairs = [
            ("base64", "exec("),
            ("base64", "eval("),
            ("b64decode", "exec("),
            ("b64decode", "subprocess"),
            ("requests.get", "exec("),
            ("urllib.request", "exec("),
            ("socket", "connect("),
        ]
        for left, right in high_risk_pairs:
            if left in text and right in text:
                score += 0.55

        regexes = [
            (r"subprocess\.(popen|call|run)\s*\(", 0.25),
            (r"os\.popen\s*\(", 0.25),
            (r"os\.system\s*\(", 0.22),
            (r"exec\s*\(", 0.30),
            (r"eval\s*\(", 0.24),
            (r"compile\s*\(", 0.10),
            (r"(requests|urllib\.request)\.(get|post|urlopen)\s*\(", 0.16),
            (r"(socket|ftplib|smtplib)\.", 0.14),
            (r"(token|password|secret|api_key|webhook)", 0.08),
        ]
        for pattern, weight in regexes:
            if re.search(pattern, text):
                score += weight

        if "os.system('clear')" in text or 'os.system("clear")' in text:
            score -= 0.18
        if "os.system('cls')" in text or 'os.system("cls")' in text:
            score -= 0.18
        if "data:image/" in text or "data:application/pdf;base64" in text:
            score -= 0.12

        return max(0.0, min(1.0, score))

    def _critical_import_targets(self, source_by_path: Mapping[str, str]) -> set[str]:
        module_to_path = self._module_index(source_by_path)
        targets: set[str] = set()
        for rel_path, source in source_by_path.items():
            if not self._is_critical_path(rel_path, source):
                continue
            for module in self._imports(source):
                candidates = self._module_candidates(module)
                for candidate in candidates:
                    path = module_to_path.get(candidate)
                    if path and path != rel_path:
                        targets.add(path)
        return targets

    def _module_index(self, source_by_path: Mapping[str, str]) -> dict[str, str]:
        index: dict[str, str] = {}
        for rel_path in source_by_path:
            path = PurePosixPath(rel_path.replace("\\", "/"))
            if path.suffix != ".py":
                continue
            parts = list(path.with_suffix("").parts)
            if parts[-1] == "__init__":
                parts = parts[:-1]
            if not parts:
                continue
            for start in range(len(parts)):
                module = ".".join(parts[start:])
                index.setdefault(module, rel_path)
        return index

    def _imports(self, source: str) -> set[str]:
        modules: set[str] = set()
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return modules
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    modules.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    modules.add(node.module)
                    for alias in node.names:
                        modules.add(f"{node.module}.{alias.name}")
        return modules

    def _module_candidates(self, module: str) -> list[str]:
        parts = module.split(".")
        return [".".join(parts[i:]) for i in range(len(parts))]

    def _risk_rationale(
        self, verdict: PackageVerdict, risks: Sequence[CalibratedFileRisk]
    ) -> str:
        top = sorted(risks, key=lambda r: r.calibrated_score, reverse=True)[:5]
        if verdict.target == 1:
            highlights = "; ".join(
                f"{r.rel_path} base={r.base_score:.2f} risk={r.calibrated_score:.2f}"
                for r in top
            )
            return (
                f"Package '{verdict.package}' is flagged as MALICIOUS by "
                f"risk-calibrated aggregation. The maximum calibrated risk "
                f"exceeds threshold {self.package_threshold:.2f}. Top files: "
                f"{highlights}."
            )
        if top:
            highlights = "; ".join(
                f"{r.rel_path} base={r.base_score:.2f} risk={r.calibrated_score:.2f}"
                for r in top[:3]
            )
        else:
            highlights = "no files"
        return (
            f"Package '{verdict.package}' is BENIGN by risk-calibrated "
            f"aggregation: no file exceeds threshold {self.package_threshold:.2f}. "
            f"Top residual risks: {highlights}."
        )


class RiskCalibratedVerdictAgentV2(RiskCalibratedVerdictAgent):
    """Second risk-calibrated aggregation strategy.

    V2 keeps the same public API as V1 but tightens the parts that created
    false positives in large benign packages:

    * import boost is inherited only from install/runtime entrypoints, not from
      every ``__init__.py``;
    * ``__init__.py`` receives a smaller critical bonus than ``setup.py``;
    * generated/resource/tooling files receive stronger penalties;
    * small packages with high-risk behavior in an entrypoint get a rescue
      boost even when CodeBERT is under-confident.
    """

    def __init__(
        self,
        llm: object | None = None,
        package_threshold: float = 0.72,
        critical_bonus: float = 0.20,
        import_bonus: float = 0.12,
        behavior_bonus: float = 0.24,
        low_confidence_penalty: float = 0.14,
        docs_examples_penalty: float = 0.42,
        tooling_penalty: float = 0.32,
        large_package_penalty: float = 0.10,
        generated_penalty: float = 0.28,
        small_package_behavior_bonus: float = 0.28,
    ) -> None:
        super().__init__(
            llm=llm,
            package_threshold=package_threshold,
            critical_bonus=critical_bonus,
            import_bonus=import_bonus,
            behavior_bonus=behavior_bonus,
            low_confidence_penalty=low_confidence_penalty,
            docs_examples_penalty=docs_examples_penalty,
            tooling_penalty=tooling_penalty,
            large_package_penalty=large_package_penalty,
        )
        self.generated_penalty = generated_penalty
        self.small_package_behavior_bonus = small_package_behavior_bonus

    def _calibrate_file(
        self,
        pred: FileClassification,
        source_by_path: Mapping[str, str],
        imported_by_critical: set[str],
        n_files: int,
    ) -> CalibratedFileRisk:
        rel_path = pred.rel_path
        source = source_by_path.get(rel_path, "")
        is_critical = self._is_critical_path(rel_path, source)
        is_imported = rel_path in imported_by_critical
        behavior = self._behavior_score(source)
        context_penalty, context_reasons = self._context_penalty(
            rel_path, is_critical, is_imported
        )

        low_penalty = (
            self.low_confidence_penalty
            if 0.50 <= pred.score < 0.82 and not is_critical and not is_imported
            else 0.0
        )
        large_penalty = self._large_package_penalty(rel_path, n_files, is_critical, is_imported)
        generated_penalty, generated_reasons = self._generated_resource_penalty(
            rel_path, is_critical, is_imported
        )

        score = pred.score
        reasons: list[str] = []

        role_bonus = self._critical_role_bonus(rel_path, source) if is_critical else 0.0
        if role_bonus:
            score += role_bonus
            reasons.append(f"critical_path_bonus={role_bonus:.2f}")
        if is_imported:
            score += self.import_bonus
            reasons.append("imported_by_entrypoint")
        if behavior > 0:
            score += self.behavior_bonus * behavior
            reasons.append(f"behavior={behavior:.2f}")

        if self._small_package_behavior_rescue(rel_path, source, behavior, n_files):
            score += self.small_package_behavior_bonus
            reasons.append("small_package_behavior_rescue")

        if low_penalty:
            score -= low_penalty
            reasons.append("low_confidence_penalty")
        if context_penalty:
            score -= context_penalty
            reasons.extend(context_reasons)
        if large_penalty:
            score -= large_penalty
            reasons.append(f"large_package_penalty={large_penalty:.2f}")
        if generated_penalty:
            score -= generated_penalty
            reasons.extend(generated_reasons)

        return CalibratedFileRisk(
            package=pred.package,
            rel_path=rel_path,
            base_score=float(pred.score),
            calibrated_score=max(0.0, min(1.0, float(score))),
            is_critical=is_critical,
            imported_by_critical=is_imported,
            behavior_score=behavior,
            context_penalty=context_penalty + large_penalty + generated_penalty,
            low_confidence_penalty=low_penalty,
            reasons=reasons,
        )

    def _critical_import_targets(self, source_by_path: Mapping[str, str]) -> set[str]:
        """Only propagate import risk from true execution entrypoints.

        V1 propagated from all critical files, including every ``__init__.py``.
        In large benign packages that makes normal modules look like execution
        chain payloads. V2 restricts propagation to setup/install/build/main
        files.
        """
        module_to_path = self._module_index(source_by_path)
        targets: set[str] = set()
        for rel_path, source in source_by_path.items():
            if not self._is_entrypoint_path(rel_path, source):
                continue
            for module in self._imports(source):
                for candidate in self._module_candidates(module):
                    path = module_to_path.get(candidate)
                    if path and path != rel_path:
                        targets.add(path)
        return targets

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

    def _critical_role_bonus(self, rel_path: str, source: str) -> float:
        path = PurePosixPath(rel_path.replace("\\", "/"))
        name = path.name.lower()
        if name == "setup.py":
            return 0.26
        if name in {"install.py", "installer.py", "post_install.py", "build.py"}:
            return 0.24
        if name == "__main__.py":
            return 0.18
        if name == "__init__.py":
            return 0.08
        if "cmdclass" in source and ("install" in source or "develop" in source):
            return 0.26
        return min(self.critical_bonus, 0.16)

    def _context_penalty(
        self, rel_path: str, is_critical: bool, imported_by_critical: bool
    ) -> tuple[float, list[str]]:
        penalty, reasons = super()._context_penalty(
            rel_path, is_critical, imported_by_critical
        )
        path = PurePosixPath(rel_path.replace("\\", "/"))
        parts = {p.lower() for p in path.parts}
        name = path.name.lower()

        # Do not exempt critical files from docs/tooling penalties when they live
        # under non-runtime areas. This handles e.g. docs_src/.../__init__.py.
        doc_or_example = {
            "docs_src",
            "docs",
            "doc",
            "examples",
            "example",
            "tutorial",
            "tutorials",
            "tests",
            "test",
            "testing",
            "benchmarks",
            "benchmark",
        }
        tooling = {"scripts", "tools", "dev", "demo", "demos", "samples", "sample"}

        if parts & doc_or_example:
            penalty = max(penalty, self.docs_examples_penalty)
            if "docs_examples_test_penalty" not in reasons:
                reasons.append("docs_examples_test_penalty")
        if parts & tooling and not imported_by_critical:
            penalty = max(penalty, self.tooling_penalty)
            if "tooling_script_penalty" not in reasons:
                reasons.append("tooling_script_penalty")
        if "health_check" in name or "tutorial" in name:
            penalty = max(penalty, self.tooling_penalty)
            if "health_tutorial_penalty" not in reasons:
                reasons.append("health_tutorial_penalty")
        return penalty, reasons

    def _large_package_penalty(
        self, rel_path: str, n_files: int, is_critical: bool, imported_by_critical: bool
    ) -> float:
        if is_critical or imported_by_critical:
            return 0.0
        if n_files >= 500:
            return 0.22
        if n_files >= 250:
            return 0.18
        if n_files >= 100:
            return 0.14
        if n_files >= 50:
            return self.large_package_penalty
        return 0.0

    def _generated_resource_penalty(
        self, rel_path: str, is_critical: bool, imported_by_critical: bool
    ) -> tuple[float, list[str]]:
        lowered = rel_path.lower().replace("\\", "/")
        name = PurePosixPath(lowered).name
        generated_markers = [
            "_version_meson.py",
            "coefficients.py",
            "resources/",
            "/valid/",
            "/invalid/",
            "parser/resources",
            "vendored-meson",
            "generated",
            "fixtures",
            "test cases",
            "tables/",
            "_builtins.py",
        ]
        if any(marker in lowered for marker in generated_markers):
            penalty = self.generated_penalty * (0.5 if is_critical or imported_by_critical else 1.0)
            return penalty, [f"generated_resource_penalty={penalty:.2f}"]
        if name.startswith("_version") or name.endswith("_coefficients.py"):
            return self.generated_penalty, [f"generated_resource_penalty={self.generated_penalty:.2f}"]
        return 0.0, []

    def _small_package_behavior_rescue(
        self, rel_path: str, source: str, behavior: float, n_files: int
    ) -> bool:
        if n_files > 3:
            return False
        if behavior < 0.85:
            return False
        return self._is_critical_path(rel_path, source) or self._is_entrypoint_path(
            rel_path, source
        )


class RiskCalibratedVerdictAgentV3(RiskCalibratedVerdictAgentV2):
    """Paper-facing RC-PAA variant.

    V3 keeps V2 scoring behavior but adds three paper-facing capabilities:

    * structured outcome fields on PackageVerdict;
    * optional LLM rationale over the structured RC-PAA outcome;
    * recursive import propagation from entrypoints, including literal dynamic
      imports such as ``__import__("mod")`` and
      ``importlib.import_module("mod")``.
    """

    def __init__(
        self,
        llm: object | None = None,
        package_threshold: float = 0.72,
        max_import_depth: int = 3,
        **kwargs,
    ) -> None:
        super().__init__(llm=llm, package_threshold=package_threshold, **kwargs)
        self.max_import_depth = max_import_depth

    def aggregate(
        self,
        package: str,
        predictions: Sequence[FileClassification],
        files: Sequence[ExtractedFile] | Mapping[str, str] | None = None,
    ) -> PackageVerdict:
        source_by_path = self._source_map(files)
        imported_by_critical = self._critical_import_targets(source_by_path)
        n_files = len(predictions)

        risks = [
            self._calibrate_file(pred, source_by_path, imported_by_critical, n_files)
            for pred in predictions
        ]
        self.last_file_risks = risks

        risk_by_path = {r.rel_path: r for r in risks}
        suspicious = [
            p
            for p in predictions
            if risk_by_path.get(p.rel_path, self._empty_risk(p)).calibrated_score
            >= self.package_threshold
        ]
        benign = [p for p in predictions if p not in suspicious]

        verdict = PackageVerdict(
            package=package,
            label="malicious" if suspicious else "benign",
            target=1 if suspicious else 0,
            malicious_files=list(suspicious),
            benign_files=benign if suspicious else list(predictions),
        )

        self._attach_structured_outcome(verdict, risks)
        if self.llm is not None:
            verdict.rationale = self._explain(verdict)
        else:
            verdict.rationale = self._risk_rationale(verdict, risks)
        return verdict

    def _critical_import_targets(self, source_by_path: Mapping[str, str]) -> set[str]:
        """Recursively propagate import risk from true execution entrypoints."""
        module_to_path = self._module_index(source_by_path)
        graph: dict[str, set[str]] = {}
        roots: list[str] = []
        for rel_path, source in source_by_path.items():
            imported_paths: set[str] = set()
            for module in self._imports(source):
                for candidate in self._module_candidates(module):
                    path = module_to_path.get(candidate)
                    if path and path != rel_path:
                        imported_paths.add(path)
            graph[rel_path] = imported_paths
            if self._is_entrypoint_path(rel_path, source):
                roots.append(rel_path)

        targets: set[str] = set()
        queue: list[tuple[str, int]] = [(root, 0) for root in roots]
        seen = set(roots)
        while queue:
            current, depth = queue.pop(0)
            if depth >= self.max_import_depth:
                continue
            for target in graph.get(current, set()):
                if target in seen:
                    continue
                seen.add(target)
                targets.add(target)
                queue.append((target, depth + 1))
        return targets

    def _imports(self, source: str) -> set[str]:
        modules = super()._imports(source)
        if not source:
            return modules
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return modules
        for node in ast.walk(tree):
            module = self._literal_dynamic_import(node)
            if module:
                modules.add(module)
        return modules

    def _literal_dynamic_import(self, node: ast.AST) -> str | None:
        if not isinstance(node, ast.Call):
            return None
        if not node.args:
            return None
        func = node.func
        if isinstance(func, ast.Name) and func.id == "__import__":
            return self._literal_string(node.args[0])
        if isinstance(func, ast.Attribute) and func.attr == "import_module":
            if isinstance(func.value, ast.Name) and func.value.id == "importlib":
                return self._literal_string(node.args[0])
        return None

    def _literal_string(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr):
            parts: list[str] = []
            for value in node.values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    parts.append(value.value)
                else:
                    return None
            return "".join(parts)
        return None

    def _attach_structured_outcome(
        self, verdict: PackageVerdict, risks: Sequence[CalibratedFileRisk]
    ) -> None:
        top = sorted(risks, key=lambda r: r.calibrated_score, reverse=True)
        trigger = top[0] if top else None
        confidence = float(trigger.calibrated_score) if trigger else 0.0
        trigger_file = trigger.rel_path if trigger else ""
        reason = self._structured_reason(verdict, trigger)
        top_risk_files = [
            {
                "path": r.rel_path,
                "base_score": round(r.base_score, 4),
                "calibrated_score": round(r.calibrated_score, 4),
                "is_critical": r.is_critical,
                "imported_by_critical": r.imported_by_critical,
                "behavior_score": round(r.behavior_score, 4),
                "reasons": r.reasons,
            }
            for r in top[:5]
        ]

        verdict.confidence = confidence
        verdict.trigger_file = trigger_file
        verdict.reason = reason
        verdict.structured_outcome = {
            "package": verdict.package,
            "verdict": verdict.label,
            "target": verdict.target,
            "confidence": confidence,
            "threshold": self.package_threshold,
            "trigger_file": trigger_file,
            "reason": reason,
            "n_files": verdict.n_files,
            "n_malicious_files": len(verdict.malicious_files),
            "top_risk_files": top_risk_files,
        }

    def _structured_reason(
        self, verdict: PackageVerdict, trigger: CalibratedFileRisk | None
    ) -> str:
        if trigger is None:
            return "No extracted Python files were available for RC-PAA aggregation."
        if verdict.target == 0:
            return (
                "No file exceeded the package risk threshold after RC-PAA "
                "context calibration."
            )
        reason_bits: list[str] = []
        if trigger.is_critical:
            reason_bits.append("critical execution file")
        if trigger.imported_by_critical:
            reason_bits.append("reachable from install/runtime entrypoint")
        if trigger.behavior_score > 0:
            reason_bits.append(f"static high-risk behavior={trigger.behavior_score:.2f}")
        if trigger.reasons:
            reason_bits.extend(trigger.reasons[:3])
        if not reason_bits:
            reason_bits.append("high calibrated CodeBERT risk")
        return "; ".join(reason_bits)

    def _build_prompt(self, verdict: PackageVerdict) -> str:
        payload = verdict.structured_outcome or verdict.to_dict()
        return (
            "You are the Verdict Agent in the LAMPS RC-PAA pipeline. "
            "Use the structured package-level RC-PAA outcome below to write a "
            "concise 3-5 sentence security rationale. Name the trigger file, "
            "confidence, key risk reasons, and whether the package should be "
            "treated as malicious or benign. Do not invent files or evidence "
            "outside the JSON payload.\n\n"
            f"{json.dumps(payload, indent=2)}"
        )
