"""Shared helpers for wardline CLI commands."""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

# Canonical coherence-issue severity map.  Imported by coherence_cmd and
# regime_cmd so the classification cannot diverge.
COHERENCE_SEVERITY_MAP: dict[str, str] = {
    "orphaned_annotation": "WARNING",
    "undeclared_boundary": "WARNING",
    "tier_distribution": "WARNING",
    "tier_downgrade": "ERROR",
    "tier_upgrade_without_evidence": "ERROR",
    "agent_originated_exception": "WARNING",
    "expired_exception": "WARNING",
    "first_scan_perimeter": "WARNING",
}


def discover_all_annotations(
    scan_path: Path,
) -> dict[tuple[str, str], list[Any]]:
    """Walk .py files under *scan_path*, parse to AST, discover annotations."""
    from wardline.scanner.discovery import discover_annotations

    all_annotations: dict[tuple[str, str], list[Any]] = {}

    for py_file in sorted(scan_path.rglob("*.py")):
        try:
            source = py_file.read_text(encoding="utf-8")
        except (OSError, PermissionError):
            continue
        try:
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError:
            continue
        file_annotations = discover_annotations(tree, py_file)
        all_annotations.update(file_annotations)

    return all_annotations
