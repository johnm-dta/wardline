"""WL002: Attribute access with fallback default.

Detects getattr(obj, name, default) — 3-arg form.
Also fires when default is passed as keyword argument.
"""

from __future__ import annotations

import ast
from typing import Iterator

_MSG = (
    "WL002 [advisory] getattr() with fallback default "
    "— run wardline scan for taint-context verdict"
)


def check_wl002(tree: ast.Module) -> Iterator[tuple[int, int, str, type]]:
    """Yield (line, col, message, type) for WL002 findings."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not (isinstance(node.func, ast.Name) and node.func.id == "getattr"):
            continue
        # 3+ positional args
        if len(node.args) >= 3:
            yield (node.lineno, node.col_offset, _MSG, type(None))
            continue
        # 2 positional args + 'default' keyword
        if len(node.args) >= 2:
            for kw in node.keywords:
                if kw.arg == "default":
                    yield (node.lineno, node.col_offset, _MSG, type(None))
                    break
