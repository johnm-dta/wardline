"""Shared helpers for wardline CLI commands."""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


def discover_all_annotations(
    scan_path: Path,
) -> dict[tuple[str, str], list]:
    """Walk .py files under *scan_path*, parse to AST, discover annotations."""
    from wardline.scanner.discovery import discover_annotations

    all_annotations: dict[tuple[str, str], list] = {}

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
