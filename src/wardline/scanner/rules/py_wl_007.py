"""PY-WL-007: Runtime type-checking on internal data.

Detects ``isinstance()`` and ``type() ==``/``type() is`` checks that
indicate runtime type-checking on data that should be statically typed.
In a tier model, internal data (Tier 1-2) should have known types —
runtime type checks suggest a trust boundary violation.

Taint-gated: the severity matrix shows SUPPRESS for EXTERNAL_RAW and
UNKNOWN_RAW (where type checks on untrusted data are expected), and
escalating severity for internal taint states.
"""

from __future__ import annotations

import ast

from wardline.core import matrix
from wardline.core.severity import RuleId, Severity
from wardline.core.taints import TaintState
from wardline.scanner.context import Finding
from wardline.scanner.rules.base import RuleBase, walk_skip_nested_defs

# PY-WL-007 suppresses at these taint states (matrix shows SUPPRESS/TRANSPARENT).
_SUPPRESS_TAINTS = frozenset({
    TaintState.EXTERNAL_RAW,
    TaintState.UNKNOWN_RAW,
})


class RulePyWl007(RuleBase):
    """Detect runtime type-checking on internal data.

    Collects findings into ``self.findings`` during AST traversal.
    The engine reads this list after rule execution.
    """

    RULE_ID = RuleId.PY_WL_007

    def __init__(self, *, file_path: str = "") -> None:
        super().__init__()
        self._file_path = file_path

    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        """Walk function body for isinstance/type checks."""
        for child in walk_skip_nested_defs(node):
            if isinstance(child, ast.Call):
                self._check_isinstance(child)
            elif isinstance(child, ast.Compare):
                self._check_type_compare(child)

    def _check_isinstance(self, call: ast.Call) -> None:
        """Check for isinstance(obj, type) calls."""
        if isinstance(call.func, ast.Name) and call.func.id == "isinstance":
            self._emit_finding(
                call,
                "Runtime type-checking — isinstance() suggests "
                "unknown type at a trust boundary",
            )

    def _check_type_compare(self, compare: ast.Compare) -> None:
        """Check for ``type(x) == T`` or ``type(x) is T`` patterns."""
        # Left side must be type(...)
        if not self._is_type_call(compare.left):
            return
        for op in compare.ops:
            if isinstance(op, (ast.Eq, ast.NotEq, ast.Is, ast.IsNot)):
                self._emit_finding(
                    compare,
                    "Runtime type-checking — type() comparison suggests "
                    "unknown type at a trust boundary",
                )
                return

    @staticmethod
    def _is_type_call(node: ast.expr) -> bool:
        """Check if node is a ``type(...)`` call."""
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "type"
        )

    def _emit_finding(self, node: ast.AST, message: str) -> None:
        """Emit a PY-WL-007 finding."""
        taint = self._get_function_taint(self._current_qualname)
        cell = matrix.lookup(self.RULE_ID, taint)
        self.findings.append(
            Finding(
                rule_id=RuleId.PY_WL_007,
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
