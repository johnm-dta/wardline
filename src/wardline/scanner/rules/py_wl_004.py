"""PY-WL-004: Broad Exception Handlers.

Detects exception handlers that catch too broadly:

- ``except:`` — bare handler catches everything including SystemExit
- ``except Exception:`` — catches all standard exceptions
- ``except BaseException:`` — catches everything explicitly
- ``except*`` (TryStar) with broad types — Python 3.11+ exception groups
"""

from __future__ import annotations

import ast

from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.scanner.context import Finding
from wardline.scanner.rules.base import RuleBase

_BROAD_NAMES = frozenset({"Exception", "BaseException"})


class RulePyWl004(RuleBase):
    """Detect broad exception handlers.

    Collects findings into ``self.findings`` during AST traversal.
    The engine reads this list after rule execution.
    """

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
        """Walk the function body looking for PY-WL-004 patterns."""
        for child in ast.walk(node):
            if isinstance(child, ast.ExceptHandler):
                self._check_handler(child, node)

    def _check_handler(
        self,
        handler: ast.ExceptHandler,
        enclosing_func: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        """Check a single ExceptHandler for broad exception patterns."""
        if handler.type is None:
            # Bare except:
            self._emit_finding(
                handler,
                "Broad exception handler — bare 'except:' catches all "
                "exceptions including SystemExit and KeyboardInterrupt",
            )
            return

        name = self._resolve_broad_name(handler.type)
        if name is not None:
            self._emit_finding(
                handler,
                f"Broad exception handler — 'except {name}' catches "
                f"overly broad exception type",
            )

    @staticmethod
    def _resolve_broad_name(node: ast.expr) -> str | None:
        """Return the broad exception name if node resolves to one, else None."""
        if isinstance(node, ast.Name) and node.id in _BROAD_NAMES:
            return node.id
        if isinstance(node, ast.Attribute) and node.attr in _BROAD_NAMES:
            return node.attr
        return None

    def _emit_finding(
        self,
        handler: ast.ExceptHandler,
        message: str,
    ) -> None:
        """Emit a PY-WL-004 finding."""
        self.findings.append(
            Finding(
                rule_id=RuleId.PY_WL_004,
                file_path=self._file_path,
                line=handler.lineno,
                col=handler.col_offset,
                end_line=handler.end_lineno,
                end_col=handler.end_col_offset,
                message=message,
                severity=Severity.ERROR,
                exceptionability=Exceptionability.STANDARD,
                taint_state=None,  # type: ignore[arg-type]
                analysis_level=1,
                source_snippet=None,
            )
        )
