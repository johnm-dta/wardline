"""PY-WL-009: Semantic validation without prior shape validation.

Detects functions that perform semantic checks (business-logic validation
on data values) without first performing shape validation (checking that
required keys/attributes exist and have expected types).

Pattern: subscript access (``data["key"]``) or attribute access in a
conditional (if/assert), where the function body has no prior shape
check — ``isinstance()``, ``hasattr()``, ``"key" in data``, or a
structural validation call (``validate_schema``, ``check_shape``, etc.).
"""

from __future__ import annotations

import ast

from wardline.core import matrix
from wardline.core.severity import RuleId
from wardline.scanner.context import Finding
from wardline.scanner.rules.base import RuleBase, walk_skip_nested_defs

# Function name fragments that indicate shape validation.
_SHAPE_VALIDATION_NAMES = frozenset({
    "validate_schema",
    "check_schema",
    "verify_schema",
    "validate_shape",
    "check_shape",
    "verify_shape",
    "validate_structure",
    "check_structure",
    "verify_structure",
})

# Substrings in function names that suggest shape validation.
_SHAPE_VALIDATION_SUBSTRINGS = ("schema", "shape", "structure")


def _has_shape_check_before(
    stmts: list[ast.stmt],
    *,
    stop_line: int,
) -> bool:
    """Check if any statement before *stop_line* is a shape validation.

    Shape validations include:
    - isinstance(...) calls
    - hasattr(...) calls
    - ``"key" in data`` / ``key in data`` comparisons
    - Calls to functions with shape-validation names
    """
    for node in ast.walk(ast.Module(body=stmts, type_ignores=[])):
        if getattr(node, "lineno", 0) >= stop_line:
            continue
        if isinstance(node, ast.Call):
            if _is_shape_validation_call(node):
                return True
        elif isinstance(node, ast.Compare) and _is_membership_test(node):
            return True
    return False


def _is_shape_validation_call(call: ast.Call) -> bool:
    """Check if a call is isinstance, hasattr, or a shape-validation function."""
    if isinstance(call.func, ast.Name):
        name = call.func.id
        if name in ("isinstance", "hasattr"):
            return True
        if name in _SHAPE_VALIDATION_NAMES:
            return True
        for sub in _SHAPE_VALIDATION_SUBSTRINGS:
            if sub in name.lower():
                return True
    if isinstance(call.func, ast.Attribute):
        attr = call.func.attr
        if attr in _SHAPE_VALIDATION_NAMES:
            return True
        for sub in _SHAPE_VALIDATION_SUBSTRINGS:
            if sub in attr.lower():
                return True
    return False


def _is_membership_test(compare: ast.Compare) -> bool:
    """Check if a Compare node is ``x in y`` or ``x not in y``."""
    return any(isinstance(op, (ast.In, ast.NotIn)) for op in compare.ops)


def _has_subscript_or_attr_access(node: ast.AST) -> bool:
    """Check if node contains a subscript or attribute access on data."""
    return any(isinstance(child, (ast.Subscript, ast.Attribute)) for child in ast.walk(node))


def _get_semantic_check_nodes(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[ast.AST]:
    """Find if/assert nodes that perform semantic checks on subscript data.

    A semantic check is an if-test or assert that accesses data via
    subscript (data["key"]) and compares or tests a value — business
    logic validation on the data's content rather than its shape.
    """
    results: list[ast.AST] = []
    for child in walk_skip_nested_defs(node):
        if (isinstance(child, (ast.If, ast.Assert))) and _has_subscript_or_attr_access(child.test):
            results.append(child)
    return results


class RulePyWl009(RuleBase):
    """Detect semantic validation without prior shape validation.

    Collects findings into ``self.findings`` during AST traversal.
    The engine reads this list after rule execution.
    """

    RULE_ID = RuleId.PY_WL_009

    def __init__(self, *, file_path: str = "") -> None:
        super().__init__()
        self._file_path = file_path

    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        """Walk function body for semantic checks without shape validation."""
        semantic_checks = _get_semantic_check_nodes(node)
        if not semantic_checks:
            return

        # For each semantic check, see if there's a shape check before it
        for check in semantic_checks:
            check_line = getattr(check, "lineno", 0)
            if not _has_shape_check_before(node.body, stop_line=check_line):
                self._emit_finding(check)

    def _emit_finding(self, node: ast.AST) -> None:
        """Emit a PY-WL-009 finding."""
        taint = self._get_function_taint(self._current_qualname)
        cell = matrix.lookup(self.RULE_ID, taint)
        self.findings.append(
            Finding(
                rule_id=RuleId.PY_WL_009,
                file_path=self._file_path,
                line=getattr(node, "lineno", 0),
                col=getattr(node, "col_offset", 0),
                end_line=getattr(node, "end_lineno", None),
                end_col=getattr(node, "end_col_offset", None),
                message=(
                    "Semantic validation without prior shape validation — "
                    "business logic check on data that has not been "
                    "structurally validated"
                ),
                severity=cell.severity,
                exceptionability=cell.exceptionability,
                taint_state=taint,
                analysis_level=1,
                source_snippet=None,
                qualname=self._current_qualname,
            )
        )
