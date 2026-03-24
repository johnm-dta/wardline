"""WL005: Silent exception handlers.

Detects exception handlers whose body is a single:
- ``pass``
- ``...`` (Ellipsis)
- ``continue``
- ``break``
"""

from __future__ import annotations

import ast
from typing import Iterator

_MSG = "WL005 [advisory] silent exception handler — run wardline scan for taint-context verdict"


def _is_silent_body(body: list[ast.stmt]) -> bool:
    """Return True if the handler body is a single silent statement."""
    if len(body) != 1:
        return False
    stmt = body[0]
    if isinstance(stmt, (ast.Pass, ast.Continue, ast.Break)):
        return True
    # Ellipsis: Expr(value=Constant(value=...))
    if (
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Constant)
        and stmt.value.value is ...
    ):
        return True
    return False


def check_wl005(tree: ast.Module) -> Iterator[tuple[int, int, str, type]]:
    """Yield (line, col, message, type) for WL005 findings."""
    _TryStar = getattr(ast, "TryStar", None)

    # Collect handler ids from TryStar to avoid double-counting
    trystar_handler_ids: set[int] = set()

    if _TryStar is not None:
        for node in ast.walk(tree):
            if isinstance(node, _TryStar):
                for handler in node.handlers:
                    trystar_handler_ids.add(id(handler))
                    if _is_silent_body(handler.body):
                        yield (handler.lineno, handler.col_offset, _MSG, type(None))

    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        if id(node) in trystar_handler_ids:
            continue
        if _is_silent_body(node.body):
            yield (node.lineno, node.col_offset, _MSG, type(None))
