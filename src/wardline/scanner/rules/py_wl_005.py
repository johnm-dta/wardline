"""PY-WL-005: Silent exception handling.

Detects exception handlers that silently swallow exceptions — the handler
body does nothing meaningful:

- ``pass`` body — ``except: pass``
- ``...`` (Ellipsis) body — ``except: ...``
- ``continue``-only body — ``except: continue``
- ``break``-only body — ``except: break``

Applies to both regular ``try/except`` and ``except*`` (ExceptionGroup)
handlers.
"""

from __future__ import annotations

import ast

from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.scanner.context import Finding
from wardline.scanner.rules.base import RuleBase

_SILENT_MESSAGES: dict[type, str] = {
    ast.Pass: (
        "Silent exception handler — 'pass' swallows exception "
        "without logging or re-raising"
    ),
    ast.Continue: (
        "Silent exception handler — 'continue' swallows exception "
        "without logging or re-raising"
    ),
    ast.Break: (
        "Silent exception handler — 'break' swallows exception "
        "without logging or re-raising"
    ),
}

_ELLIPSIS_MESSAGE = (
    "Silent exception handler — '...' swallows exception "
    "without logging or re-raising"
)


def _is_ellipsis_stmt(stmt: ast.stmt) -> bool:
    """Check if a statement is a bare ``...`` (Ellipsis literal)."""
    return (
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Constant)
        and stmt.value.value is ...
    )


def _silent_message(stmt: ast.stmt) -> str | None:
    """Return the finding message if *stmt* is a silent handler body, else None."""
    for node_type, msg in _SILENT_MESSAGES.items():
        if isinstance(stmt, node_type):
            return msg
    if _is_ellipsis_stmt(stmt):
        return _ELLIPSIS_MESSAGE
    return None


class RulePyWl005(RuleBase):
    """Detect silent exception handlers.

    Collects findings into ``self.findings`` during AST traversal.
    The engine reads this list after rule execution.
    """

    RULE_ID = RuleId.PY_WL_005

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
        """Walk the function body looking for silent exception handlers."""
        # Collect handlers from TryStar nodes to avoid double-counting
        # (TryStar.handlers are ExceptHandler nodes that ast.walk also yields).
        _TryStar = getattr(ast, "TryStar", None)
        trystar_handlers: set[int] = set()
        if _TryStar is not None:
            for child in ast.walk(node):
                if isinstance(child, _TryStar):
                    for handler in child.handlers:
                        trystar_handlers.add(id(handler))
                        self._check_handler(handler)

        for child in ast.walk(node):
            if (
                isinstance(child, ast.ExceptHandler)
                and id(child) not in trystar_handlers
            ):
                self._check_handler(child)

    def _check_handler(self, handler: ast.ExceptHandler) -> None:
        """Check a single exception handler for silent body."""
        if len(handler.body) != 1:
            return
        stmt = handler.body[0]
        message = _silent_message(stmt)
        if message is None:
            return
        self.findings.append(
            Finding(
                rule_id=RuleId.PY_WL_005,
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
