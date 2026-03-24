"""WL003: Existence checking as structural gate.

Detects:
- ``key in d`` / ``key not in d`` — in/not-in operators
- ``hasattr(obj, name)`` — attribute existence check
- match/case with MatchMapping / MatchClass (3.10+ only, guarded)
"""

from __future__ import annotations

import ast
from typing import Iterator

_MSG = (
    "WL003 [advisory] existence checking as structural gate "
    "— run wardline scan for taint-context verdict"
)


def check_wl003(tree: ast.Module) -> Iterator[tuple[int, int, str, type]]:
    """Yield (line, col, message, type) for WL003 findings."""
    _MatchMapping = getattr(ast, "MatchMapping", None)
    _MatchClass = getattr(ast, "MatchClass", None)

    for node in ast.walk(tree):
        # Pattern 1: in / not in
        if isinstance(node, ast.Compare):
            for op in node.ops:
                if isinstance(op, (ast.In, ast.NotIn)):
                    yield (node.lineno, node.col_offset, _MSG, type(None))
                    break
            continue

        # Pattern 2: hasattr()
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == "hasattr":
                yield (node.lineno, node.col_offset, _MSG, type(None))
            continue

        # Pattern 3: match/case — MatchMapping (3.10+)
        if _MatchMapping is not None and isinstance(node, _MatchMapping):
            yield (
                getattr(node, "lineno", 0),
                getattr(node, "col_offset", 0),
                _MSG,
                type(None),
            )
            continue

        # Pattern 4: match/case — MatchClass (3.10+)
        if _MatchClass is not None and isinstance(node, _MatchClass):
            yield (
                getattr(node, "lineno", 0),
                getattr(node, "col_offset", 0),
                _MSG,
                type(None),
            )
            continue
