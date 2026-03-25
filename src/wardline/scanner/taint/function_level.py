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


# ── Decorator → TaintState mappings ──────────────────────────────
#
# Body evaluation taint: the taint state rules evaluate at INSIDE
# the function body. Per spec §A.4.3, validators evaluate at the
# INPUT tier (the data they receive), not the OUTPUT tier.
BODY_EVAL_TAINT: dict[str, TaintState] = {
    "external_boundary": TaintState.EXTERNAL_RAW,
    "validates_shape": TaintState.EXTERNAL_RAW,      # input: T4
    "validates_semantic": TaintState.SHAPE_VALIDATED,  # input: T3
    "validates_external": TaintState.EXTERNAL_RAW,     # input: T4
    "tier1_read": TaintState.AUDIT_TRAIL,
    "audit_writer": TaintState.AUDIT_TRAIL,
    "authoritative_construction": TaintState.AUDIT_TRAIL,
}

# Return value taint: the taint state assigned to the function's
# return value for propagation to callers. This is the OUTPUT tier.
RETURN_TAINT: dict[str, TaintState] = {
    "external_boundary": TaintState.EXTERNAL_RAW,
    "validates_shape": TaintState.SHAPE_VALIDATED,     # output: T3
    "validates_semantic": TaintState.PIPELINE,          # output: T2
    "validates_external": TaintState.PIPELINE,          # output: T2
    "tier1_read": TaintState.AUDIT_TRAIL,
    "audit_writer": TaintState.AUDIT_TRAIL,
    "authoritative_construction": TaintState.AUDIT_TRAIL,
}

# Structural invariant: both maps must cover exactly the same decorators.
# If a decorator is added to one but not the other, taint assignment will
# silently produce wrong values (the fallback masks the error).
if set(BODY_EVAL_TAINT) != set(RETURN_TAINT):
    _only_body = set(BODY_EVAL_TAINT) - set(RETURN_TAINT)
    _only_ret = set(RETURN_TAINT) - set(BODY_EVAL_TAINT)
    raise ValueError(
        f"BODY_EVAL_TAINT and RETURN_TAINT key sets diverge: "
        f"only in BODY={_only_body}, only in RETURN={_only_ret}"
    )

# Backward-compatible alias for explain_cmd.py and other importers.
DECORATOR_TAINT_MAP = BODY_EVAL_TAINT


# ── Public API ───────────────────────────────────────────────────


def assign_function_taints(
    tree: ast.Module,
    file_path: Path | str,
    annotations: dict[tuple[str, str], list[WardlineAnnotation]],
    manifest: WardlineManifest | None = None,
) -> tuple[dict[str, TaintState], dict[str, TaintState], dict[str, TaintSource]]:
    """Assign taint states to every function in a parsed module.

    Args:
        tree: Parsed AST module.
        file_path: Path to the source file.
        annotations: Decorator annotations from ``discover_annotations()``.
        manifest: Loaded manifest (for ``module_tiers`` lookup).
            ``None`` means no manifest — all undecorated functions get
            ``UNKNOWN_RAW``.

    Returns:
        Tuple of (body_taint_map, return_taint_map, taint_sources) where:
        - body_taint_map: dict mapping qualname → ``TaintState`` for rule
          evaluation inside function bodies (INPUT tier).
        - return_taint_map: dict mapping qualname → ``TaintState`` for
          return value taint propagation (OUTPUT tier).
        - taint_sources: dict mapping qualname → ``TaintSource``
          indicating which branch assigned the taint ("decorator",
          "module_default", or "fallback").
    """
    path_str = str(file_path)
    module_default = resolve_module_default(path_str, manifest)
    body_taint_map: dict[str, TaintState] = {}
    return_taint_map: dict[str, TaintState] = {}
    taint_sources: dict[str, TaintSource] = {}

    _walk_and_assign(
        tree, path_str, annotations, module_default,
        body_taint_map, return_taint_map, taint_sources,
        scope="",
    )

    return body_taint_map, return_taint_map, taint_sources


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
    taint_map: dict[str, TaintState] | None = None,
) -> TaintState | None:
    """Resolve taint from decorator annotations.

    If multiple taint-assigning decorators are present, returns the
    first one found. (Multiple taint decorators on a single function
    is unusual and will be flagged by later rules.)

    Args:
        taint_map: Which decorator→taint mapping to use. Defaults to
            ``BODY_EVAL_TAINT`` (input tier).
    """
    if taint_map is None:
        taint_map = BODY_EVAL_TAINT
    key = (file_path, qualname)
    anns = annotations.get(key)
    if not anns:
        return None

    for ann in anns:
        taint = taint_map.get(ann.canonical_name)
        if taint is not None:
            return taint

    return None


def _walk_and_assign(
    node: ast.AST,
    file_path: str,
    annotations: dict[tuple[str, str], list[WardlineAnnotation]],
    module_default: TaintState | None,
    body_taint_map: dict[str, TaintState],
    return_taint_map: dict[str, TaintState],
    taint_sources: dict[str, TaintSource],
    scope: str,
) -> None:
    """Recursively walk AST nodes, assigning taint to each function."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            qualname = f"{scope}.{child.name}" if scope else child.name

            # Precedence: decorator > module_tiers > UNKNOWN_RAW
            body_taint = taint_from_annotations(
                file_path, qualname, annotations, taint_map=BODY_EVAL_TAINT,
            )
            if body_taint is not None:
                source: TaintSource = "decorator"
                ret_taint = taint_from_annotations(
                    file_path, qualname, annotations, taint_map=RETURN_TAINT,
                )
                # Fallback: if decorator is in BODY_EVAL_TAINT but not
                # RETURN_TAINT, use body taint for return too.
                if ret_taint is None:
                    ret_taint = body_taint
            elif module_default is not None:
                body_taint = module_default
                ret_taint = module_default
                source = "module_default"
            else:
                body_taint = TaintState.UNKNOWN_RAW
                ret_taint = TaintState.UNKNOWN_RAW
                source = "fallback"

            body_taint_map[qualname] = body_taint
            return_taint_map[qualname] = ret_taint
            taint_sources[qualname] = source

            # Recurse into nested functions/methods
            _walk_and_assign(
                child, file_path, annotations, module_default,
                body_taint_map, return_taint_map, taint_sources,
                scope=qualname,
            )
        elif isinstance(child, ast.ClassDef):
            class_scope = (
                f"{scope}.{child.name}" if scope else child.name
            )
            _walk_and_assign(
                child, file_path, annotations, module_default,
                body_taint_map, return_taint_map, taint_sources,
                scope=class_scope,
            )
        else:
            _walk_and_assign(
                child, file_path, annotations, module_default,
                body_taint_map, return_taint_map, taint_sources,
                scope=scope,
            )
