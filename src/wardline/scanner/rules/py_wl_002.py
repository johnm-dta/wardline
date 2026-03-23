"""PY-WL-002: Attribute access with fallback default.

Detects three-argument ``getattr(obj, name, default)`` calls where the
default silently fabricates a value for a missing attribute, bypassing
validation.

Only the 3-arg form fires — 2-arg ``getattr`` (which raises
``AttributeError`` on missing attributes) is not flagged.
``hasattr()`` is handled separately by PY-WL-003.
"""

from __future__ import annotations

import ast

from wardline.core import matrix
from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.scanner.context import Finding
from wardline.scanner.rules.base import RuleBase, walk_skip_nested_defs


class RulePyWl002(RuleBase):
    """Detect attribute access with fallback default patterns.

    Collects findings into ``self.findings`` during AST traversal.
    The engine reads this list after rule execution.
    """

    RULE_ID = RuleId.PY_WL_002

    def __init__(self, *, file_path: str = "") -> None:
        super().__init__()
        self._file_path = file_path

    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        """Walk the function body looking for PY-WL-002 patterns."""
        for child in walk_skip_nested_defs(node):
            if not isinstance(child, ast.Call):
                continue
            self._check_call(child, node)

    def _check_call(
        self,
        call: ast.Call,
        enclosing_func: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        """Check a single Call node for 3-arg getattr()."""
        if (
            isinstance(call.func, ast.Name)
            and call.func.id == "getattr"
            and len(call.args) >= 3
        ):
            self._emit_finding(call, enclosing_func)

    def _emit_finding(
        self,
        call: ast.Call,
        enclosing_func: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        """Emit a PY-WL-002 finding."""
        taint = self._get_function_taint(self._current_qualname)
        cell = matrix.lookup(self.RULE_ID, taint)
        self.findings.append(
            Finding(
                rule_id=RuleId.PY_WL_002,
                file_path=self._file_path,
                line=call.lineno,
                col=call.col_offset,
                end_line=call.end_lineno,
                end_col=call.end_col_offset,
                message=(
                    "Attribute access with fallback default — "
                    "getattr() with default silently fabricates "
                    "value for missing attribute"
                ),
                severity=cell.severity,
                exceptionability=cell.exceptionability,
                taint_state=taint,
                analysis_level=1,
                source_snippet=None,
                qualname=self._current_qualname,
            )
        )
