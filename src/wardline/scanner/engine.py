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
from typing import TYPE_CHECKING

from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.scanner.context import Finding, ScanContext
from wardline.scanner.discovery import discover_annotations
from wardline.scanner.taint.function_level import assign_function_taints

if TYPE_CHECKING:
    from collections.abc import Callable

    from wardline.manifest.models import BoundaryEntry, WardlineManifest
    from wardline.scanner.rules.base import RuleBase

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
    ) -> None:
        self._target_paths = target_paths
        self._exclude_paths = tuple(p.resolve() for p in exclude_paths)
        self._rules = rules
        self._manifest = manifest
        self._boundaries = boundaries

    def scan(self) -> ScanResult:
        """Run a full scan across all target paths.

        Returns a ``ScanResult`` with all findings, counts, and errors.
        """
        result = ScanResult()

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
            taint_map = assign_function_taints(
                tree, file_path, annotations, self._manifest
            )
        except Exception as exc:
            logger.warning("Discovery/taint failed for %s: %s", file_path, exc)
            result.errors.append(
                f"Discovery/taint failed for {file_path}: {exc}"
            )
            taint_map = {}

        ctx = ScanContext(
            file_path=str(file_path),
            function_level_taint_map=taint_map,
            boundaries=self._boundaries,
        )

        # Pass 2: Run rules with context
        for rule in self._rules:
            rule.set_context(ctx)
            self._run_rule(rule, tree, file_path, result)

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
                )
            )

    @staticmethod
    def _walk_error_handler(result: ScanResult) -> Callable[[OSError], None]:
        """Return an onerror callback for os.walk."""

        def handler(error: OSError) -> None:
            logger.warning("Directory walk error: %s", error)
            result.errors.append(f"Directory walk error: {error}")

        return handler
