"""PY-WL-008: Declared boundary with no rejection path.

Detects declared validation and restoration boundaries whose bodies do
not contain a structural rejection path. Under the authoritative
binding/spec contract, WL-007 applies to the boundary function itself:
the body must reject invalid input via a raised exception or a guarded
early return that clearly represents rejection.
"""

from __future__ import annotations

import ast

from wardline.core import matrix
from wardline.core.severity import RuleId
from wardline.manifest.scope import path_within_scope
from wardline.scanner.context import Finding
from wardline.scanner.rules.base import RuleBase, walk_skip_nested_defs

_BOUNDARY_TRANSITIONS = frozenset({
    "shape_validation",
    "semantic_validation",
    "external_validation",
    "combined_validation",
    "restoration",
})

_BOUNDARY_DECORATORS = frozenset({
    "validates_shape",
    "validates_semantic",
    "validates_external",
    "restoration_boundary",
})


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
    """Return True when the branch contains a terminating rejection action."""
    for stmt in stmts:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Raise):
                return True
            if isinstance(node, ast.Return):
                return True
    return False


def _decorator_name(decorator: ast.expr) -> str | None:
    """Return the terminal decorator name for ``@name`` and ``@pkg.name``."""
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    return None


def _has_direct_boundary_decorator(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    """Check for direct wardline boundary decorators in source."""
    return any(
        _decorator_name(decorator) in _BOUNDARY_DECORATORS
        for decorator in node.decorator_list
    )


def _has_rejection_path(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True when the boundary body contains a structural rejection path."""
    for child in walk_skip_nested_defs(node):
        if isinstance(child, ast.Raise):
            return True
        if not isinstance(child, ast.If):
            continue
        if _is_negative_guard(child.test) and _branch_has_rejection_terminator(child.body):
            return True
        if child.orelse and _branch_has_rejection_terminator(child.orelse):
            return True
    return False


class RulePyWl008(RuleBase):
    """Detect declared boundaries with no rejection path.

    Collects findings into ``self.findings`` during AST traversal.
    The engine reads this list after rule execution.
    """

    RULE_ID = RuleId.PY_WL_008

    def __init__(self, *, file_path: str = "") -> None:
        super().__init__()
        self._file_path = file_path

    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        """Walk declared boundary bodies for a structural rejection path."""
        if not self._is_checked_boundary(node):
            return
        if _has_rejection_path(node):
            return
        self._emit_finding(node)

    def _is_checked_boundary(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> bool:
        """Return True for validation/restoration boundaries under this rule."""
        if self._context is not None:
            for boundary in self._context.boundaries:
                if (
                    boundary.function == self._current_qualname
                    and boundary.transition in _BOUNDARY_TRANSITIONS
                    and path_within_scope(self._file_path, boundary.overlay_scope)
                ):
                    return True
        return _has_direct_boundary_decorator(node)

    def _emit_finding(self, node: ast.AST) -> None:
        """Emit a PY-WL-008 finding."""
        taint = self._get_function_taint(self._current_qualname)
        cell = matrix.lookup(self.RULE_ID, taint)
        self.findings.append(
            Finding(
                rule_id=RuleId.PY_WL_008,
                file_path=self._file_path,
                line=getattr(node, "lineno", 0),
                col=getattr(node, "col_offset", 0),
                end_line=getattr(node, "end_lineno", None),
                end_col=getattr(node, "end_col_offset", None),
                message=(
                    "Declared validation/restoration boundary has no "
                    "rejection path"
                ),
                severity=cell.severity,
                exceptionability=cell.exceptionability,
                taint_state=taint,
                analysis_level=1,
                source_snippet=None,
                qualname=self._current_qualname,
            )
        )
