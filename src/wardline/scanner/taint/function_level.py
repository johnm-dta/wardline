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
from typing import TYPE_CHECKING, Literal

from wardline.core.taints import TaintState

if TYPE_CHECKING:
    from pathlib import Path

    from wardline.manifest.models import WardlineManifest
    from wardline.scanner.context import WardlineAnnotation

TaintSource = Literal["decorator", "module_default", "fallback"]

logger = logging.getLogger(__name__)


# ── Decorator → TaintState mapping ───────────────────────────────

# Maps canonical decorator names to the taint state they assign.
# Decorators not in this table (e.g., audit_critical) are flag-only
# and do not influence taint assignment.
DECORATOR_TAINT_MAP: dict[str, TaintState] = {
    "external_boundary": TaintState.EXTERNAL_RAW,
    "validates_shape": TaintState.SHAPE_VALIDATED,
    "validates_semantic": TaintState.PIPELINE,
    "validates_external": TaintState.PIPELINE,
    "tier1_read": TaintState.AUDIT_TRAIL,
    "audit_writer": TaintState.AUDIT_TRAIL,
    "authoritative_construction": TaintState.AUDIT_TRAIL,
}


# ── Public API ───────────────────────────────────────────────────


def assign_function_taints(
    tree: ast.Module,
    file_path: Path | str,
    annotations: dict[tuple[str, str], list[WardlineAnnotation]],
    manifest: WardlineManifest | None = None,
) -> tuple[dict[str, TaintState], dict[str, TaintSource]]:
    """Assign taint states to every function in a parsed module.

    Args:
        tree: Parsed AST module.
        file_path: Path to the source file.
        annotations: Decorator annotations from ``discover_annotations()``.
        manifest: Loaded manifest (for ``module_tiers`` lookup).
            ``None`` means no manifest — all undecorated functions get
            ``UNKNOWN_RAW``.

    Returns:
        Tuple of (taint_map, taint_sources) where:
        - taint_map: dict mapping qualname → ``TaintState``
        - taint_sources: dict mapping qualname → ``TaintSource``
          indicating which branch assigned the taint ("decorator",
          "module_default", or "fallback").
    """
    path_str = str(file_path)
    module_default = resolve_module_default(path_str, manifest)
    taint_map: dict[str, TaintState] = {}
    taint_sources: dict[str, TaintSource] = {}

    _walk_and_assign(
        tree, path_str, annotations, module_default, taint_map, taint_sources,
        scope="",
    )

    return taint_map, taint_sources


# ── Internal helpers ─────────────────────────────────────────────


def resolve_module_default(
    file_path: str,
    manifest: WardlineManifest | None,
) -> TaintState | None:
    """Find the module_tiers default taint for a file path.

    Uses proper path-prefix matching: ``entry.path`` must be a prefix
    of ``file_path`` at a directory boundary. When multiple entries
    match, the most-specific (longest path) wins.

    Returns ``None`` if no manifest or no matching module_tiers entry.
    """
    if manifest is None:
        return None

    from pathlib import PurePath

    file_p = PurePath(file_path)

    # Collect all matching entries
    matches: list[tuple[int, str]] = []
    for entry in manifest.module_tiers:
        entry_p = PurePath(entry.path)
        try:
            file_p.relative_to(entry_p)
        except ValueError:
            continue
        matches.append((len(entry.path), entry.default_taint))

    if not matches:
        return None

    # Most-specific match wins (longest path)
    matches.sort(key=lambda x: x[0], reverse=True)
    best_taint = matches[0][1]

    try:
        return TaintState(best_taint)
    except ValueError:
        logger.warning(
            "Invalid taint state '%s' in module_tiers for file '%s'",
            best_taint,
            file_path,
        )
        return None


def taint_from_annotations(
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
    taint_sources: dict[str, TaintSource],
    scope: str,
) -> None:
    """Recursively walk AST nodes, assigning taint to each function."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            qualname = f"{scope}.{child.name}" if scope else child.name

            # Precedence: decorator > module_tiers > UNKNOWN_RAW
            taint = taint_from_annotations(file_path, qualname, annotations)
            if taint is not None:
                source: TaintSource = "decorator"
            elif module_default is not None:
                taint = module_default
                source = "module_default"
            else:
                taint = TaintState.UNKNOWN_RAW
                source = "fallback"

            taint_map[qualname] = taint
            taint_sources[qualname] = source

            # Recurse into nested functions/methods
            _walk_and_assign(
                child, file_path, annotations, module_default,
                taint_map, taint_sources, scope=qualname,
            )
        elif isinstance(child, ast.ClassDef):
            class_scope = (
                f"{scope}.{child.name}" if scope else child.name
            )
            _walk_and_assign(
                child, file_path, annotations, module_default,
                taint_map, taint_sources, scope=class_scope,
            )
        else:
            _walk_and_assign(
                child, file_path, annotations, module_default,
                taint_map, taint_sources, scope=scope,
            )
