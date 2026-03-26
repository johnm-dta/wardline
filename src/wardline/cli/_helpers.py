"""Shared helpers for wardline CLI commands."""

from __future__ import annotations

import ast
import logging
from typing import TYPE_CHECKING, Any

import click

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)


def cli_error(msg: str) -> None:
    """Print structured error to stderr with consistent 'error:' prefix."""
    click.echo(f"error: {msg}", err=True)


# Canonical coherence-issue severity map.  Imported by coherence_cmd and
# regime_cmd so the classification cannot diverge.
COHERENCE_SEVERITY_MAP: dict[str, str] = {
    "orphaned_annotation": "WARNING",
    "undeclared_boundary": "WARNING",
    "unmatched_contract": "WARNING",
    "stale_contract_binding": "WARNING",
    "tier_distribution": "WARNING",
    "tier_topology_inconsistency": "ERROR",
    "tier_downgrade": "ERROR",
    "tier_upgrade_without_evidence": "ERROR",
    "agent_originated_exception": "WARNING",
    "expired_exception": "WARNING",
    "first_scan_perimeter": "WARNING",
    "missing_validation_scope": "ERROR",
    "insufficient_restoration_evidence": "ERROR",
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
        except (OSError, PermissionError) as exc:
            logger.warning("Cannot read %s: %s", py_file, exc)
            continue
        try:
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError:
            logger.debug("Skipping unparseable file: %s", py_file)
            continue
        file_annotations = discover_annotations(tree, py_file)
        all_annotations.update(file_annotations)

    return all_annotations
