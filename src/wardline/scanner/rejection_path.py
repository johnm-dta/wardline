"""Shared rejection-path analysis for two-hop resolution.

This module provides reusable functions for detecting structural rejection
paths inside AST function bodies.  A "rejection path" is a branch that
terminates with a raised exception or guarded early return, indicating
that invalid input is explicitly rejected.

These helpers are consumed by PY-WL-008 (boundary rejection) and by the
planned two-hop resolution rules that need to verify rejection across
call boundaries.
"""

from __future__ import annotations

import ast

from wardline.scanner.rules.base import walk_skip_nested_defs

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BUILTIN_KNOWN_VALIDATORS: frozenset[str] = frozenset({
    "jsonschema.validate",
    "jsonschema.Draft4Validator.validate",
    "jsonschema.Draft7Validator.validate",
    "pydantic.TypeAdapter.validate_python",
    "pydantic.BaseModel.model_validate",
    "marshmallow.Schema.load",
    "marshmallow.Schema.loads",
})

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _is_negative_guard(expr: ast.expr) -> bool:
    """Return True for simple guards that indicate rejection on this branch."""
    if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.Not):
        return True
    if isinstance(expr, ast.Compare):
        return any(
            isinstance(op, (ast.IsNot, ast.NotEq))
            or (
                isinstance(op, (ast.Is, ast.Eq))
                and isinstance(comparator, ast.Constant)
                and comparator.value in (False, None)
            )
            for op, comparator in zip(expr.ops, expr.comparators, strict=False)
        )
    return False


def _branch_has_rejection_terminator(stmts: list[ast.stmt]) -> bool:
    """Return True when the branch contains a terminating rejection action.

    Uses ``walk_skip_nested_defs`` so that a ``raise`` inside a nested
    function or class does not count as a rejection for the *outer* scope.
    """
    for stmt in stmts:
        for node in walk_skip_nested_defs(stmt):
            if isinstance(node, ast.Raise):
                return True
            if isinstance(node, ast.Return):
                return True
    return False


def _is_constant_false(expr: ast.expr) -> bool:
    """Return True for expressions that are trivially always falsy.

    Covers ``False``, ``0``, ``""``, ``b""``, ``None``, ``0.0``, ``0j``.
    """
    if not isinstance(expr, ast.Constant):
        return False
    return not expr.value and expr.value is not ...


def _is_inside_dead_branch(
    target: ast.AST,
    root: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    """Return True when *target* is nested inside a constant-false ``if`` body.

    Uses ``walk_skip_nested_defs`` so that dead branches inside nested
    functions or classes are not considered for the outer scope.
    """
    for stmt in walk_skip_nested_defs(root):
        if not isinstance(stmt, ast.If):
            continue
        if not _is_constant_false(stmt.test):
            continue
        # Check if target is inside this dead branch's body
        for body_node in walk_skip_nested_defs(stmt):
            if body_node is target:
                return True
    return False


def _has_rejection_path(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True when the boundary body contains a structural rejection path.

    A raise inside a trivially unreachable branch (``if False:``, ``if 0:``)
    is not counted as a rejection path per spec S7.2.
    """
    for child in walk_skip_nested_defs(node):
        if isinstance(child, ast.Raise) and not _is_inside_dead_branch(child, node):
            return True
        if not isinstance(child, ast.If):
            continue
        if _is_constant_false(child.test):
            continue
        if _is_negative_guard(child.test) and _branch_has_rejection_terminator(child.body):
            return True
        if child.orelse and _branch_has_rejection_terminator(child.orelse):
            return True
    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

#: Public alias for use by other modules.
has_rejection_path = _has_rejection_path
