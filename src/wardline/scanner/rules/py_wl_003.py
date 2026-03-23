"""PY-WL-003: Existence-checking as structural gate.

Detects patterns that check for the existence of a key/attribute as a
structural gate:

- ``"key" in d`` / ``key in d.keys()`` — ``in`` operator on containers
- ``"key" not in d`` — ``not in`` is still an existence check
- ``hasattr(obj, "name")`` — existence check on attributes
- ``match/case`` with ``MatchMapping`` — structural pattern on mappings
- ``match/case`` with ``MatchClass`` — structural pattern on classes
"""

from __future__ import annotations

import ast

from wardline.core import matrix
from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.core.taints import TaintState
from wardline.scanner.context import Finding
from wardline.scanner.rules.base import RuleBase

# PY-WL-003 only fires at these taint states.
# MIXED_RAW included: matrix shows (E,St) same as EXTERNAL_RAW/UNKNOWN_RAW.
# Temporary divergence from matrix for suppressed states — the matrix shows
# (E,U) at AUDIT_TRAIL/PIPELINE/SHAPE_VALIDATED but we suppress here because
# "key in config" is a normal pattern in safe contexts, not a structural gate.
# Tracked: wardline-a87ea844eb (reconcile _ACTIVE_TAINTS with matrix)
_ACTIVE_TAINTS = frozenset({
    TaintState.EXTERNAL_RAW,
    TaintState.UNKNOWN_RAW,
    TaintState.MIXED_RAW,
})


class RulePyWl003(RuleBase):
    """Detect existence-checking as structural gate patterns.

    Collects findings into ``self.findings`` during AST traversal.
    The engine reads this list after rule execution.
    """

    RULE_ID = RuleId.PY_WL_003

    def __init__(self, *, file_path: str = "") -> None:
        super().__init__()
        self._file_path = file_path

    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        """Walk the function body looking for PY-WL-003 patterns."""
        taint = self._get_function_taint(self._current_qualname)
        if taint not in _ACTIVE_TAINTS:
            return
        for child in ast.walk(node):
            if isinstance(child, ast.Compare):
                self._check_compare(child, node, taint)
            elif isinstance(child, ast.Call):
                self._check_hasattr(child, node, taint)
            elif isinstance(child, ast.MatchMapping):
                self._emit_finding(
                    child,
                    node,
                    "Existence check as structural gate — "
                    "structural pattern match on mapping",
                    taint,
                )
            elif isinstance(child, ast.MatchClass):
                self._emit_finding(
                    child,
                    node,
                    "Existence check as structural gate — "
                    "structural pattern match on class",
                    taint,
                )

    def _check_compare(
        self,
        compare: ast.Compare,
        enclosing_func: ast.FunctionDef | ast.AsyncFunctionDef,
        taint: TaintState,
    ) -> None:
        """Check a Compare node for ``in`` / ``not in`` operators."""
        for op in compare.ops:
            if isinstance(op, (ast.In, ast.NotIn)):
                self._emit_finding(
                    compare,
                    enclosing_func,
                    "Existence check as structural gate — "
                    "'in' operator used for key/attribute presence check",
                    taint,
                )
                return

    def _check_hasattr(
        self,
        call: ast.Call,
        enclosing_func: ast.FunctionDef | ast.AsyncFunctionDef,
        taint: TaintState,
    ) -> None:
        """Check a Call node for ``hasattr(obj, name)``."""
        if isinstance(call.func, ast.Name) and call.func.id == "hasattr":
            self._emit_finding(
                call,
                enclosing_func,
                "Existence check as structural gate — "
                "hasattr() used for attribute presence check",
                taint,
            )

    def _emit_finding(
        self,
        node: ast.AST,
        enclosing_func: ast.FunctionDef | ast.AsyncFunctionDef,
        message: str,
        taint: TaintState,
    ) -> None:
        """Emit a PY-WL-003 finding."""
        cell = matrix.lookup(RuleId.PY_WL_003, taint)
        self.findings.append(
            Finding(
                rule_id=RuleId.PY_WL_003,
                file_path=self._file_path,
                line=getattr(node, "lineno", 0),
                col=getattr(node, "col_offset", 0),
                end_line=getattr(node, "end_lineno", None),
                end_col=getattr(node, "end_col_offset", None),
                message=message,
                severity=cell.severity,
                exceptionability=cell.exceptionability,
                taint_state=taint,
                analysis_level=1,
                source_snippet=None,
                qualname=self._current_qualname,
            )
        )
