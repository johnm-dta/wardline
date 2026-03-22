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

from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.scanner.context import Finding
from wardline.scanner.rules.base import RuleBase


class RulePyWl003(RuleBase):
    """Detect existence-checking as structural gate patterns.

    Collects findings into ``self.findings`` during AST traversal.
    The engine reads this list after rule execution.
    """

    RULE_ID = RuleId.PY_WL_003

    def __init__(self, *, file_path: str = "", taint_state: str = "") -> None:
        super().__init__()
        self._file_path = file_path
        self._taint_state = taint_state

    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        """Walk the function body looking for PY-WL-003 patterns."""
        for child in ast.walk(node):
            if isinstance(child, ast.Compare):
                self._check_compare(child, node)
            elif isinstance(child, ast.Call):
                self._check_hasattr(child, node)
            elif isinstance(child, ast.MatchMapping):
                self._emit_finding(
                    child,
                    node,
                    "Existence check as structural gate — "
                    "structural pattern match on mapping",
                )
            elif isinstance(child, ast.MatchClass):
                self._emit_finding(
                    child,
                    node,
                    "Existence check as structural gate — "
                    "structural pattern match on class",
                )

    def _check_compare(
        self,
        compare: ast.Compare,
        enclosing_func: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        """Check a Compare node for ``in`` / ``not in`` operators."""
        for op in compare.ops:
            if isinstance(op, (ast.In, ast.NotIn)):
                self._emit_finding(
                    compare,
                    enclosing_func,
                    "Existence check as structural gate — "
                    "'in' operator used for key/attribute presence check",
                )
                return

    def _check_hasattr(
        self,
        call: ast.Call,
        enclosing_func: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        """Check a Call node for ``hasattr(obj, name)``."""
        if isinstance(call.func, ast.Name) and call.func.id == "hasattr":
            self._emit_finding(
                call,
                enclosing_func,
                "Existence check as structural gate — "
                "hasattr() used for attribute presence check",
            )

    def _emit_finding(
        self,
        node: ast.AST,
        enclosing_func: ast.FunctionDef | ast.AsyncFunctionDef,
        message: str,
    ) -> None:
        """Emit a PY-WL-003 finding."""
        self.findings.append(
            Finding(
                rule_id=RuleId.PY_WL_003,
                file_path=self._file_path,
                line=getattr(node, "lineno", 0),
                col=getattr(node, "col_offset", 0),
                end_line=getattr(node, "end_lineno", None),
                end_col=getattr(node, "end_col_offset", None),
                message=message,
                severity=Severity.ERROR,
                exceptionability=Exceptionability.STANDARD,
                taint_state=None,
                analysis_level=1,
                source_snippet=None,
            )
        )
