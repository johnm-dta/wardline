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

from wardline.core.severity import RuleId
from wardline.scanner.rules.base import RuleBase, iter_exception_handlers

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

    def __init__(self, *, file_path: str = "") -> None:
        super().__init__()
        self._file_path = file_path

    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        """Walk the function body looking for silent exception handlers."""
        for handler in iter_exception_handlers(node):
            self._check_handler(handler)

    def _check_handler(self, handler: ast.ExceptHandler) -> None:
        """Check a single exception handler for silent body."""
        if len(handler.body) != 1:
            return
        stmt = handler.body[0]
        message = _silent_message(stmt)
        if message is None:
            return
        self._emit_matrix_finding(handler, message)
