"""PY-WL-001: Dict key access with fallback default.

Detects patterns where code silently fabricates values for missing
dictionary keys, bypassing validation:

- ``d.get(key, default)`` — ``.get()`` with a default argument
- ``d.setdefault(key, default)`` — mutates dict with fabricated default
- ``defaultdict(factory)`` — constructor registers a default factory

``schema_default()`` suppresses to a WARNING-severity finding with
rule ID ``PY-WL-001-UNVERIFIED-DEFAULT`` (overlay verification is
not yet implemented in MVP).
"""

from __future__ import annotations

import ast

from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.scanner.context import Finding
from wardline.scanner.rules.base import RuleBase


class RulePyWl001(RuleBase):
    """Detect dict key access with fallback default patterns.

    Collects findings into ``self.findings`` during AST traversal.
    The engine reads this list after rule execution.
    """

    RULE_ID = RuleId.PY_WL_001

    def __init__(self, *, file_path: str = "", taint_state: str = "") -> None:
        self.findings: list[Finding] = []
        self._file_path = file_path
        self._taint_state = taint_state

    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        """Walk the function body looking for PY-WL-001 patterns."""
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            self._check_call(child, node)

    def _check_call(
        self,
        call: ast.Call,
        enclosing_func: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        """Check a single Call node for PY-WL-001 patterns."""
        # Pattern 1: d.get(key, default) — .get() with ≥2 args
        if self._is_method_call(call, "get") and len(call.args) >= 2:
            if self._is_schema_default_arg(call.args[1]):
                self._emit_unverified_default(call, enclosing_func)
            else:
                self._emit_finding(call, enclosing_func)
            return

        # Pattern 2: d.setdefault(key, default)
        if self._is_method_call(call, "setdefault") and len(call.args) >= 2:
            if self._is_schema_default_arg(call.args[1]):
                self._emit_unverified_default(call, enclosing_func)
            else:
                self._emit_finding(call, enclosing_func)
            return

        # Pattern 3: defaultdict(factory)
        if self._is_defaultdict_call(call):
            self._emit_finding(call, enclosing_func)

    @staticmethod
    def _is_method_call(call: ast.Call, method_name: str) -> bool:
        """Check if call is ``x.method_name(...)``."""
        return (
            isinstance(call.func, ast.Attribute)
            and call.func.attr == method_name
        )

    @staticmethod
    def _is_defaultdict_call(call: ast.Call) -> bool:
        """Check if call is ``defaultdict(...)``."""
        return isinstance(call.func, ast.Name) and call.func.id == "defaultdict"

    @staticmethod
    def _is_schema_default_arg(node: ast.expr) -> bool:
        """Check if an argument is ``schema_default(...)``."""
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "schema_default"
        )

    def _emit_finding(
        self,
        call: ast.Call,
        enclosing_func: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        """Emit a PY-WL-001 finding."""
        self.findings.append(
            Finding(
                rule_id=RuleId.PY_WL_001,
                file_path=self._file_path,
                line=call.lineno,
                col=call.col_offset,
                end_line=call.end_lineno,
                end_col=call.end_col_offset,
                message=(
                    "Dict key access with fallback default — "
                    "value fabricated for missing key without validation"
                ),
                severity=Severity.ERROR,
                exceptionability=Exceptionability.STANDARD,
                taint_state=None,  # type: ignore[arg-type]
                analysis_level=1,
                source_snippet=None,
            )
        )

    def _emit_unverified_default(
        self,
        call: ast.Call,
        enclosing_func: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        """Emit a PY-WL-001-UNVERIFIED-DEFAULT WARNING."""
        self.findings.append(
            Finding(
                rule_id=RuleId.PY_WL_001_UNVERIFIED_DEFAULT,
                file_path=self._file_path,
                line=call.lineno,
                col=call.col_offset,
                end_line=call.end_lineno,
                end_col=call.end_col_offset,
                message=(
                    "schema_default() suppresses PY-WL-001 but overlay "
                    "verification is not yet implemented — this "
                    "suppression is un-governed"
                ),
                severity=Severity.WARNING,
                exceptionability=Exceptionability.UNCONDITIONAL,
                taint_state=None,  # type: ignore[arg-type]
                analysis_level=1,
                source_snippet=None,
            )
        )
