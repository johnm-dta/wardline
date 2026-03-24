"""WL004: Broad exception handlers.

Detects:
- bare ``except:``
- ``except Exception`` / ``except BaseException``
- qualified names: ``builtins.Exception``
- tuple handlers with a broad member: ``except (Exception, ValueError)``
- ``except*`` (TryStar) with broad types (3.11+, guarded)
"""

from __future__ import annotations

import ast
from typing import Iterator

_BROAD_NAMES = frozenset({"Exception", "BaseException"})

_MSG = "WL004 [advisory] broad exception handler — run wardline scan for taint-context verdict"


def _is_broad(node: ast.expr) -> bool:
    """Return True if the exception type expression contains a broad name."""
    if isinstance(node, ast.Name) and node.id in _BROAD_NAMES:
        return True
    if isinstance(node, ast.Attribute) and node.attr in _BROAD_NAMES:
        return True
    if isinstance(node, ast.Tuple):
        for elt in node.elts:
            if isinstance(elt, ast.Name) and elt.id in _BROAD_NAMES:
                return True
            if isinstance(elt, ast.Attribute) and elt.attr in _BROAD_NAMES:
                return True
    return False


def check_wl004(tree: ast.Module) -> Iterator[tuple[int, int, str, type]]:
    """Yield (line, col, message, type) for WL004 findings."""
    _TryStar = getattr(ast, "TryStar", None)

    # Collect handler ids from TryStar to avoid double-counting
    trystar_handler_ids: set[int] = set()

    if _TryStar is not None:
        for node in ast.walk(tree):
            if isinstance(node, _TryStar):
                for handler in node.handlers:
                    trystar_handler_ids.add(id(handler))
                    if handler.type is None or _is_broad(handler.type):
                        yield (handler.lineno, handler.col_offset, _MSG, type(None))

    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        if id(node) in trystar_handler_ids:
            continue
        # Bare except
        if node.type is None:
            yield (node.lineno, node.col_offset, _MSG, type(None))
            continue
        # Named broad handler
        if _is_broad(node.type):
            yield (node.lineno, node.col_offset, _MSG, type(None))
