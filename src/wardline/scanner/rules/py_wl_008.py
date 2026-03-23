"""PY-WL-008: Validation with no rejection path.

Detects functions that call validation-like functions, capture the
result, but never use that result in a conditional (if/assert/raise)
to reject invalid data.  The validation computes a pass/fail verdict
but the function ignores it — creating false security.

Structural-conditional definition (wardline-5c56619b22): a *rejection
path* is an ``if``/``assert``/``raise`` that references the variable
holding the validation result.
"""

from __future__ import annotations

import ast

from wardline.core import matrix
from wardline.core.severity import RuleId
from wardline.scanner.context import Finding
from wardline.scanner.rules.base import RuleBase, walk_skip_nested_defs

# Substrings in function names that indicate validation.
_VALIDATION_SUBSTRINGS = ("valid", "check", "verify", "sanitize", "inspect")


def _is_validation_call(call: ast.Call) -> bool:
    """Check if a function call looks like a validation function."""
    name = _call_name(call)
    if name is None:
        return False
    lower = name.lower()
    return any(sub in lower for sub in _VALIDATION_SUBSTRINGS)


def _call_name(call: ast.Call) -> str | None:
    """Extract the simple name from a Call node."""
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return None


def _find_validation_assignments(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[tuple[str, ast.Assign | ast.AnnAssign]]:
    """Find assignments where the RHS is a validation call.

    Returns (variable_name, assignment_node) pairs.
    """
    results: list[tuple[str, ast.Assign | ast.AnnAssign]] = []
    for child in walk_skip_nested_defs(node):
        if isinstance(child, ast.Assign) and len(child.targets) == 1:
            target = child.targets[0]
            if (
                isinstance(target, ast.Name)
                and isinstance(child.value, ast.Call)
                and _is_validation_call(child.value)
            ):
                results.append((target.id, child))
        elif isinstance(child, ast.AnnAssign):
            if (
                child.value is not None
                and isinstance(child.target, ast.Name)
                and isinstance(child.value, ast.Call)
                and _is_validation_call(child.value)
            ):
                results.append((child.target.id, child))
    return results


def _variable_used_in_rejection_path(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    var_name: str,
) -> bool:
    """Check if *var_name* is used in an if-test, assert, or raise.

    This is the structural-conditional definition: a rejection path
    exists if the variable appears in:
    - The test of an ``if`` statement
    - The test of an ``assert`` statement
    - A ``raise`` statement (the variable is the exception or part of it)
    """
    for child in walk_skip_nested_defs(node):
        if isinstance(child, ast.If):
            if _name_appears_in(child.test, var_name):
                return True
        elif isinstance(child, ast.Assert):
            if _name_appears_in(child.test, var_name):
                return True
        elif isinstance(child, ast.Raise):
            if child.exc is not None and _name_appears_in(child.exc, var_name):
                return True
        elif isinstance(child, ast.Call):
            # Check for patterns like: abort_if_invalid(result)
            # where the variable is passed to a function that rejects
            if _name_appears_in(child, var_name) and _is_rejection_call(child):
                return True
    return False


def _is_rejection_call(call: ast.Call) -> bool:
    """Check if a call looks like a rejection function (abort, reject, fail)."""
    name = _call_name(call)
    if name is None:
        return False
    lower = name.lower()
    return any(
        sub in lower
        for sub in ("abort", "reject", "fail", "raise", "deny", "refuse")
    )


def _name_appears_in(node: ast.AST, name: str) -> bool:
    """Check if an ``ast.Name`` with id == *name* appears anywhere in *node*."""
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id == name:
            return True
    return False


class RulePyWl008(RuleBase):
    """Detect validation with no rejection path.

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
        """Walk function body for validation calls without rejection paths."""
        assignments = _find_validation_assignments(node)
        if not assignments:
            return

        for var_name, assign_node in assignments:
            if not _variable_used_in_rejection_path(node, var_name):
                self._emit_finding(assign_node)

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
                    "Validation with no rejection path — "
                    "validation result is captured but never used "
                    "to reject invalid data"
                ),
                severity=cell.severity,
                exceptionability=cell.exceptionability,
                taint_state=taint,
                analysis_level=1,
                source_snippet=None,
                qualname=self._current_qualname,
            )
        )
