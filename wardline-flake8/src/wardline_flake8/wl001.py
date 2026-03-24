"""WL001: Dict key access with fallback default.

Detects:
- d.get(key, default) — .get() with >=2 args
- d.setdefault(key, default) — .setdefault() with >=2 args
- defaultdict(factory) — constructor with factory arg
"""

from __future__ import annotations

import ast
from typing import Iterator

_MSG = (
    "WL001 [advisory] dict.get() / setdefault() / defaultdict() "
    "with fallback default — run wardline scan for taint-context verdict"
)


def check_wl001(tree: ast.Module) -> Iterator[tuple[int, int, str, type]]:
    """Yield (line, col, message, type) for WL001 findings."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        # Pattern 1: x.get(key, default) — >=2 args
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and len(node.args) >= 2
        ):
            yield (node.lineno, node.col_offset, _MSG, type(None))
            continue

        # Pattern 2: x.setdefault(key, default) — >=2 args
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "setdefault"
            and len(node.args) >= 2
        ):
            yield (node.lineno, node.col_offset, _MSG, type(None))
            continue

        # Pattern 3: defaultdict(factory) — >=1 arg
        if len(node.args) >= 1:
            if isinstance(node.func, ast.Name) and node.func.id == "defaultdict":
                yield (node.lineno, node.col_offset, _MSG, type(None))
                continue
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "defaultdict"
            ):
                yield (node.lineno, node.col_offset, _MSG, type(None))
                continue
