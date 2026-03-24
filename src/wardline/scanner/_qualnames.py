"""Shared qualname utilities — iterative AST walk for building qualname maps.

Extracted from ``ScanEngine`` for reuse by both the engine and call-graph
taint analysis (L3).
"""

from __future__ import annotations

import ast


def build_qualname_map(tree: ast.Module) -> dict[int, str]:
    """Build ``{id(node): qualname}`` for all functions/async functions in *tree*.

    Uses an iterative (stack-based) walk to avoid Python's recursion limit on
    deeply nested modules.
    """
    result: dict[int, str] = {}

    # Stack entries: (node_to_visit, current_scope_parts)
    stack: list[tuple[ast.AST, list[str]]] = [(tree, [])]

    while stack:
        node, scope = stack.pop()

        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                stack.append((child, scope + [child.name]))
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualname = ".".join(scope + [child.name])
                result[id(child)] = qualname
                stack.append((child, scope + [child.name]))

    return result
