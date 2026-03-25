"""ScanEngine — orchestrates file discovery, AST parsing, and rule execution.

The engine walks the project tree (``os.walk(followlinks=False)``),
filters files against the manifest perimeter, parses each ``.py`` file
into an AST, and runs every enabled rule against every file.

Error handling philosophy:
- **Parse errors**: skip the file, log a warning, continue the scan.
- **Permission errors**: skip the directory/file, log a warning, continue.
- **Rule crashes**: catch the exception, emit a ``TOOL-ERROR`` finding,
  continue with remaining rules and files.
"""

from __future__ import annotations

import ast
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING

from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.scanner._qualnames import build_qualname_map
from wardline.scanner.context import Finding, ScanContext, WardlineAnnotation
from wardline.scanner.discovery import discover_annotations
from wardline.scanner.taint.callgraph import extract_call_edges
from wardline.scanner.taint.callgraph_propagation import (
    TaintProvenance,
    propagate_callgraph_taints,
)
from wardline.scanner.taint.function_level import assign_function_taints
from wardline.scanner.taint.variable_level import compute_variable_taints

if TYPE_CHECKING:
    from collections.abc import Callable

    from wardline.core.taints import TaintState
    from wardline.core.taints import TaintState as _TS
    from wardline.manifest.models import BoundaryEntry, OptionalFieldEntry, WardlineManifest
    from wardline.scanner.rules.base import RuleBase
    from wardline.scanner.taint.function_level import TaintSource

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Aggregated result of a scan run."""

    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    errors: list[str] = field(default_factory=list)


class ScanEngine:
    """Orchestrates file discovery → AST parsing → rule execution.

    Args:
        target_paths: Root directories to scan.
        exclude_paths: Paths to exclude from scanning (resolved against
            each target for prefix matching).
        rules: Rule instances to execute against each file's AST.
    """

    def __init__(
        self,
        *,
        target_paths: tuple[Path, ...],
        exclude_paths: tuple[Path, ...] = (),
        rules: tuple[RuleBase, ...] = (),
        manifest: WardlineManifest | None = None,
        boundaries: tuple[BoundaryEntry, ...] = (),
        optional_fields: tuple[OptionalFieldEntry, ...] = (),
        analysis_level: int = 1,
    ) -> None:
        self._target_paths = target_paths
        self._exclude_paths = tuple(p.resolve() for p in exclude_paths)
        self._rules = rules
        self._manifest = manifest
        self._boundaries = boundaries
        self._optional_fields = optional_fields
        self._analysis_level = analysis_level
        self._project_annotations: MappingProxyType[
            tuple[str, str], tuple[WardlineAnnotation, ...]
        ] | None = None
        self._module_file_map: MappingProxyType[str, str] | None = None
        self._string_literal_counts: MappingProxyType[str, int] | None = None

    def scan(self) -> ScanResult:
        """Run a full scan across all target paths.

        Returns a ``ScanResult`` with all findings, counts, and errors.
        """
        result = ScanResult()
        (
            self._project_annotations,
            self._module_file_map,
            self._string_literal_counts,
        ) = self._build_project_indexes()

        for target in self._target_paths:
            resolved_target = target.resolve()
            if not resolved_target.is_dir():
                logger.warning("Target path is not a directory: %s", target)
                result.errors.append(f"Target path is not a directory: {target}")
                continue
            self._scan_tree(resolved_target, result)

        return result

    def _scan_tree(self, root: Path, result: ScanResult) -> None:
        """Walk a directory tree and scan all .py files."""
        try:
            onerror = self._walk_error_handler(result)
            walker = os.walk(root, followlinks=False, onerror=onerror)
        except OSError as exc:
            logger.warning("Cannot access target directory %s: %s", root, exc)
            result.errors.append(f"Cannot access target directory {root}: {exc}")
            return

        for dirpath, dirnames, filenames in walker:
            dir_resolved = Path(dirpath).resolve()

            # Prune excluded directories in-place (prevents os.walk descent)
            dirnames[:] = [
                d
                for d in dirnames
                if not self._is_excluded(dir_resolved / d)
            ]

            for filename in filenames:
                if not filename.endswith(".py"):
                    continue

                file_path = dir_resolved / filename
                if self._is_excluded(file_path):
                    continue

                self._scan_file(file_path, result)

    def _is_excluded(self, path: Path) -> bool:
        """Check if a resolved path falls under any exclude path."""
        resolved = path.resolve()
        for excluded in self._exclude_paths:
            try:
                resolved.relative_to(excluded)
                return True
            except ValueError:
                continue
        return False

    def _scan_file(self, file_path: Path, result: ScanResult) -> None:
        """Parse a single file and run all rules against its AST."""
        try:
            source = file_path.read_text(encoding="utf-8")
        except PermissionError as exc:
            logger.warning("Permission denied reading %s: %s", file_path, exc)
            result.files_skipped += 1
            result.errors.append(f"Permission denied: {file_path}")
            return
        except OSError as exc:
            logger.warning("Cannot read %s: %s", file_path, exc)
            result.files_skipped += 1
            result.errors.append(f"Cannot read {file_path}: {exc}")
            return

        try:
            tree = ast.parse(source, filename=str(file_path))
        except SyntaxError as exc:
            logger.warning("Syntax error in %s: %s", file_path, exc)
            result.files_skipped += 1
            result.errors.append(f"Syntax error in {file_path}: {exc}")
            return

        result.files_scanned += 1

        # Pass 1: Discovery + taint assignment (fault-tolerant)
        try:
            annotations = discover_annotations(tree, file_path)
            body_taint_map, return_taint_map, taint_sources = assign_function_taints(
                tree, file_path, annotations, self._manifest
            )
        except Exception as exc:
            logger.warning("Discovery/taint failed for %s: %s", file_path, exc)
            result.errors.append(
                f"Discovery/taint failed for {file_path}: {exc}"
            )
            body_taint_map, return_taint_map, taint_sources = {}, {}, {}

        # Pass 1.5: Level 3 call-graph taint (when analysis_level >= 3)
        # L3 refines body_taint_map using callgraph analysis. The refined map
        # is still a body-evaluation map (what rules see inside function bodies),
        # but non-anchored functions may be demoted based on their callees'
        # return taints.
        taint_provenance: dict[str, TaintProvenance] | None = None
        if self._analysis_level >= 3 and body_taint_map:
            body_taint_map, taint_provenance = self._run_callgraph_taint(
                tree, body_taint_map, taint_sources, file_path, result,
                return_taint_map=return_taint_map,
            )

        # Pass 1.75: Level 2 variable-level taint (when analysis_level >= 2)
        variable_taint_map: dict[str, dict[str, TaintState]] | None = None
        if self._analysis_level >= 2 and body_taint_map:
            variable_taint_map = self._run_variable_taint(
                tree, body_taint_map, return_taint_map, taint_sources,
                file_path, result,
            )

        ctx = ScanContext(
            file_path=str(file_path),
            function_level_taint_map=body_taint_map,  # type: ignore[arg-type]  # __post_init__ converts dict → MappingProxyType
            annotations_map={  # type: ignore[arg-type]  # __post_init__ converts dict → MappingProxyType
                qualname: tuple(found)
                for (ann_path, qualname), found in annotations.items()
                if ann_path == str(file_path)
            },
            project_annotations_map=self._project_annotations,
            module_file_map=self._module_file_map,
            string_literal_counts=self._string_literal_counts,
            boundaries=self._boundaries,
            optional_fields=self._optional_fields,
            variable_taint_map=variable_taint_map,  # type: ignore[arg-type]  # __post_init__ converts dict → MappingProxyType
            analysis_level=self._analysis_level,
            taint_provenance=taint_provenance,  # type: ignore[arg-type]  # __post_init__ converts dict → MappingProxyType
        )

        # Pass 2: Run rules with context
        for rule in self._rules:
            rule.set_context(ctx)
            self._run_rule(rule, tree, file_path, result)

    def _build_project_indexes(
        self,
    ) -> tuple[
        MappingProxyType[tuple[str, str], tuple[WardlineAnnotation, ...]],
        MappingProxyType[str, str],
        MappingProxyType[str, int],
    ]:
        """Build project-wide discovery indexes before rule execution.

        This keeps cross-file rules deterministic regardless of scan order.
        Files that cannot be read or parsed are skipped here; the main scan pass
        still reports those errors authoritatively.
        """
        all_annotations: dict[tuple[str, str], tuple[WardlineAnnotation, ...]] = {}
        module_file_map: dict[str, str] = {}
        string_literal_counts: dict[str, int] = {}

        for root in self._target_paths:
            resolved_root = root.resolve()
            if not resolved_root.is_dir():
                continue
            for file_path in self._iter_python_files(resolved_root):
                module_name = self._module_name_for(resolved_root, file_path)
                if module_name is not None:
                    module_file_map[module_name] = str(file_path)
                try:
                    source = file_path.read_text(encoding="utf-8")
                    tree = ast.parse(source, filename=str(file_path))
                except (OSError, SyntaxError):
                    continue

                for node in ast.walk(tree):
                    if (
                        isinstance(node, ast.Constant)
                        and isinstance(node.value, str)
                        and node.value
                    ):
                        string_literal_counts[node.value] = (
                            string_literal_counts.get(node.value, 0) + 1
                        )

                discovered = discover_annotations(tree, file_path)
                for key, value in discovered.items():
                    all_annotations[key] = tuple(value)

        return (
            MappingProxyType(all_annotations),
            MappingProxyType(module_file_map),
            MappingProxyType(string_literal_counts),
        )

    def _iter_python_files(self, root: Path) -> list[Path]:
        """Collect scan-eligible Python files beneath *root*."""
        files: list[Path] = []
        try:
            walker = os.walk(root, followlinks=False)
        except OSError:
            return files

        for dirpath, dirnames, filenames in walker:
            dir_resolved = Path(dirpath).resolve()
            dirnames[:] = [
                d
                for d in dirnames
                if not self._is_excluded(dir_resolved / d)
            ]
            for filename in filenames:
                if not filename.endswith(".py"):
                    continue
                file_path = dir_resolved / filename
                if not self._is_excluded(file_path):
                    files.append(file_path)
        return files

    def _module_name_for(self, root: Path, file_path: Path) -> str | None:
        """Derive a best-effort importable module name for a source file."""
        try:
            rel = file_path.relative_to(root)
        except ValueError:
            return None
        parts = list(rel.with_suffix("").parts)
        if not parts:
            return None
        if parts[-1] == "__init__":
            parts = parts[:-1]
        if not parts:
            return None
        return ".".join(parts)

    def _run_variable_taint(
        self,
        tree: ast.Module,
        taint_map: dict[str, TaintState],
        return_taint_map: dict[str, TaintState],
        taint_sources: dict[str, TaintSource],
        file_path: Path,
        result: ScanResult,
    ) -> dict[str, dict[str, TaintState]] | None:
        """Run Level 2 variable-level taint on all functions in the AST.

        Returns a dict mapping qualname -> {variable: TaintState}, or None
        on failure.
        """
        # Build callee resolution map: for decorator-anchored callees, use
        # the return (OUTPUT) tier taint so that `x = validates_shape(data)`
        # assigns SHAPE_VALIDATED to x. For non-anchored callees, keep the
        # L3-refined body taint (which equals return taint at L1, but may
        # have been demoted by L3 callgraph analysis).
        callee_taint_map: dict[str, TaintState] = dict(taint_map)
        for qn, src in taint_sources.items():
            if src == "decorator" and qn in return_taint_map:
                callee_taint_map[qn] = return_taint_map[qn]

        var_map: dict[str, dict[str, _TS]] = {}
        qualname_map = self._build_qualname_map(tree)
        try:
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    qualname = qualname_map.get(id(node))
                    if qualname is not None and qualname in taint_map:
                        func_taint = taint_map[qualname]
                        var_taints = compute_variable_taints(
                            node, func_taint, callee_taint_map
                        )
                        var_map[qualname] = var_taints
        except Exception as exc:
            logger.warning(
                "Variable-level taint failed for %s: %s", file_path, exc
            )
            result.errors.append(
                f"Variable-level taint failed for {file_path}: {exc}"
            )
            return None

        return var_map if var_map else None

    def _run_callgraph_taint(
        self,
        tree: ast.Module,
        taint_map: dict[str, TaintState],
        taint_sources: dict[str, TaintSource],
        file_path: Path,
        result: ScanResult,
        *,
        return_taint_map: dict[str, TaintState],
    ) -> tuple[dict[str, TaintState], dict[str, TaintProvenance] | None]:
        """Run Level 3 call-graph taint propagation.

        On success, returns the refined taint map and provenance records.
        On failure, emits a TOOL-ERROR finding and returns the original
        taint map with no provenance.
        """
        try:
            qualname_map = self._build_qualname_map(tree)
            edges, resolved_counts, unresolved_counts = extract_call_edges(
                tree, qualname_map
            )
            refined_map, provenance, l3_diagnostics = propagate_callgraph_taints(
                edges, taint_map, taint_sources, resolved_counts, unresolved_counts,
                return_taint_map=return_taint_map,
            )
            # Convert L3 diagnostics to Finding objects
            _diag_rule_map = {
                "L3_CONVERGENCE_BOUND": RuleId.L3_CONVERGENCE_BOUND,
                "L3_LOW_RESOLUTION": RuleId.L3_LOW_RESOLUTION,
            }
            for diag_code, diag_msg in l3_diagnostics:
                diag_rule = _diag_rule_map.get(diag_code)
                if diag_rule is not None:
                    result.findings.append(
                        Finding(
                            rule_id=diag_rule,
                            file_path=str(file_path),
                            line=1,
                            col=0,
                            end_line=None,
                            end_col=None,
                            message=diag_msg,
                            severity=Severity.WARNING,
                            exceptionability=Exceptionability.UNCONDITIONAL,
                            taint_state=None,
                            analysis_level=3,
                            source_snippet=None,
                            qualname=None,
                        )
                    )
            return refined_map, provenance
        except Exception as exc:
            logger.warning(
                "L3 call-graph taint failed for %s: %s", file_path, exc
            )
            result.errors.append(
                f"L3 call-graph taint failed for {file_path}: {exc}"
            )
            result.findings.append(
                Finding(
                    rule_id=RuleId.TOOL_ERROR,
                    file_path=str(file_path),
                    line=1,
                    col=0,
                    end_line=None,
                    end_col=None,
                    message=(
                        f"L3 call-graph taint failed: "
                        f"{type(exc).__name__}: {exc}"
                    ),
                    severity=Severity.ERROR,
                    exceptionability=Exceptionability.UNCONDITIONAL,
                    taint_state=None,
                    analysis_level=0,
                    source_snippet=None,
                    qualname=None,
                )
            )
            return taint_map, None

    @staticmethod
    def _build_qualname_map(tree: ast.Module) -> dict[int, str]:
        """Build {id(node): qualname} for all functions in the module.

        Delegates to the shared iterative implementation in ``scanner._qualnames``.
        """
        return build_qualname_map(tree)

    def _run_rule(
        self,
        rule: RuleBase,
        tree: ast.Module,
        file_path: Path,
        result: ScanResult,
    ) -> None:
        """Execute a single rule, catching crashes as TOOL-ERROR findings."""
        try:
            # Reset findings for this file (context already set via set_context)
            rule.findings.clear()

            rule.visit(tree)

            # Collect findings from the rule into the result
            result.findings.extend(rule.findings)
        except Exception as exc:
            logger.error(
                "Rule %s crashed on %s: %s",
                type(rule).__name__,
                file_path,
                exc,
            )
            result.findings.append(
                Finding(
                    rule_id=RuleId.TOOL_ERROR,
                    file_path=str(file_path),
                    line=1,
                    col=0,
                    end_line=None,
                    end_col=None,
                    message=(
                        f"Rule {type(rule).__name__} crashed: "
                        f"{type(exc).__name__}: {exc}"
                    ),
                    severity=Severity.WARNING,
                    exceptionability=Exceptionability.UNCONDITIONAL,
                    taint_state=None,
                    analysis_level=0,
                    source_snippet=None,
                    qualname=None,
                )
            )

    @staticmethod
    def _walk_error_handler(result: ScanResult) -> Callable[[OSError], None]:
        """Return an onerror callback for os.walk."""

        def handler(error: OSError) -> None:
            logger.warning("Directory walk error: %s", error)
            result.errors.append(f"Directory walk error: {error}")

        return handler
