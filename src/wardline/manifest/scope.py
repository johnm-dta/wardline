"""Shared helpers for overlay-scope path matching."""

from __future__ import annotations

from pathlib import Path


def path_within_scope(file_path: str, overlay_scope: str) -> bool:
    """Return True when *file_path* is inside *overlay_scope*.

    Uses ``Path.relative_to`` so sibling directories like ``src/apiary``
    do not incorrectly match an overlay rooted at ``src/api``.
    """
    if not file_path or not overlay_scope:
        return False

    resolved_file = Path(file_path).resolve()
    resolved_scope = Path(overlay_scope).resolve()
    try:
        resolved_file.relative_to(resolved_scope)
        return True
    except ValueError:
        return False


def relative_path_within_scope(path: str, scope: str) -> bool:
    """Return True when a project-relative *path* is inside *scope*.

    Used for validating that an overlay file's on-disk directory is
    actually covered by the relative ``overlay_for`` path it claims.
    """
    if not path or not scope:
        return False

    path_obj = Path(path)
    scope_obj = Path(scope)
    try:
        path_obj.relative_to(scope_obj)
        return True
    except ValueError:
        return False


def scope_specificity(overlay_scope: str) -> int:
    """Return a stable specificity score for an overlay scope path."""
    if not overlay_scope:
        return -1
    return len(Path(overlay_scope).resolve().parts)
