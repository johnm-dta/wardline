"""Level 1 taint assignment — per-function taint from decorators and manifest.

Assigns a ``TaintState`` to every function in the scanned codebase using
three sources in strict precedence order:

1. **Decorator taint** (highest) — if the function has a wardline decorator
   that maps to a taint state, use it.
2. **Module tiers** — if the function's file path matches a declared
   ``module_tiers`` entry in the manifest, use that module's default taint.
3. **UNKNOWN_RAW** (fallback) — if neither applies.

This precedence is a security invariant: a function explicitly decorated
``@external_boundary`` in a module with a "safe" default taint must still
get ``EXTERNAL_RAW``.
"""

from __future__ import annotations

import ast
import logging
from typing import TYPE_CHECKING

from wardline.core.taints import TaintState

if TYPE_CHECKING:
    from pathlib import Path

    from wardline.manifest.models import WardlineManifest
    from wardline.scanner.context import WardlineAnnotation

logger = logging.getLogger(__name__)


# ── Decorator → TaintState mapping ───────────────────────────────

# Maps canonical decorator names to the taint state they assign.
# Decorators not in this table (e.g., audit_critical) are flag-only
# and do not influence taint assignment.
DECORATOR_TAINT_MAP: dict[str, TaintState] = {
    "external_boundary": TaintState.EXTERNAL_RAW,
    "validates_shape": TaintState.SHAPE_VALIDATED,
    "validates_semantic": TaintState.UNKNOWN_SEM_VALIDATED,
    "validates_external": TaintState.SHAPE_VALIDATED,
    "tier1_read": TaintState.AUDIT_TRAIL,
    "audit_writer": TaintState.AUDIT_TRAIL,
    "authoritative_construction": TaintState.PIPELINE,
}


# ── Public API ───────────────────────────────────────────────────


def assign_function_taints(
    tree: ast.Module,
    file_path: Path | str,
    annotations: dict[tuple[str, str], list[WardlineAnnotation]],
    manifest: WardlineManifest | None = None,
) -> dict[str, TaintState]:
    """Assign taint states to every function in a parsed module.

    Args:
        tree: Parsed AST module.
        file_path: Path to the source file.
        annotations: Decorator annotations from ``discover_annotations()``.
        manifest: Loaded manifest (for ``module_tiers`` lookup).
            ``None`` means no manifest — all undecorated functions get
            ``UNKNOWN_RAW``.

    Returns:
        Dict mapping qualname → ``TaintState`` for every function
        (sync and async) in the module.
    """
    path_str = str(file_path)
    module_default = _resolve_module_default(path_str, manifest)
    taint_map: dict[str, TaintState] = {}

    _walk_and_assign(
        tree, path_str, annotations, module_default, taint_map, scope=""
    )

    return taint_map


# ── Internal helpers ─────────────────────────────────────────────


def _resolve_module_default(
    file_path: str,
    manifest: WardlineManifest | None,
) -> TaintState | None:
    """Find the module_tiers default taint for a file path.

    Returns ``None`` if no manifest or no matching module_tiers entry.
    """
    if manifest is None:
        return None

    for entry in manifest.module_tiers:
        # Match if the file path contains the declared module path
        # This handles both exact matches and subdirectory matches
        if entry.path in file_path:
            try:
                return TaintState(entry.default_taint)
            except ValueError:
                logger.warning(
                    "Invalid taint state '%s' in module_tiers for path '%s'",
                    entry.default_taint,
                    entry.path,
                )
                return None

    return None


def _taint_from_annotations(
    file_path: str,
    qualname: str,
    annotations: dict[tuple[str, str], list[WardlineAnnotation]],
) -> TaintState | None:
    """Resolve taint from decorator annotations.

    If multiple taint-assigning decorators are present, returns the
    first one found. (Multiple taint decorators on a single function
    is unusual and will be flagged by later rules.)
    """
    key = (file_path, qualname)
    anns = annotations.get(key)
    if not anns:
        return None

    for ann in anns:
        taint = DECORATOR_TAINT_MAP.get(ann.canonical_name)
        if taint is not None:
            return taint

    return None


def _walk_and_assign(
    node: ast.AST,
    file_path: str,
    annotations: dict[tuple[str, str], list[WardlineAnnotation]],
    module_default: TaintState | None,
    taint_map: dict[str, TaintState],
    scope: str,
) -> None:
    """Recursively walk AST nodes, assigning taint to each function."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            qualname = f"{scope}.{child.name}" if scope else child.name

            # Precedence: decorator > module_tiers > UNKNOWN_RAW
            taint = _taint_from_annotations(file_path, qualname, annotations)
            if taint is None:
                taint = (
                    module_default
                    if module_default is not None
                    else TaintState.UNKNOWN_RAW
                )

            taint_map[qualname] = taint

            # Recurse into nested functions/methods
            _walk_and_assign(
                child, file_path, annotations, module_default,
                taint_map, scope=qualname,
            )
        elif isinstance(child, ast.ClassDef):
            class_scope = (
                f"{scope}.{child.name}" if scope else child.name
            )
            _walk_and_assign(
                child, file_path, annotations, module_default,
                taint_map, scope=class_scope,
            )
        else:
            _walk_and_assign(
                child, file_path, annotations, module_default,
                taint_map, scope=scope,
            )
