"""Shared qualname resolution from AST.

The scope-stack walk mirrors RuleBase._dispatch and visit_ClassDef:
function/class names form dotted qualnames like "ClassName.method_name".
"""

from __future__ import annotations

import ast


def find_function_node(
    tree: ast.Module,
    qualname: str,
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Find a function/method node in *tree* by dotted qualname.

    Walks the AST using scope matching to find ``qualname`` (e.g.,
    ``"MyClass.handle"`` or ``"outer.inner"``).
    Returns the matching node, or None if not found.
    """
    parts = qualname.split(".")
    return _search(tree, parts, 0)


def _search(
    node: ast.AST,
    parts: list[str],
    depth: int,
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Recursively search for the function matching parts[depth:]."""
    if depth >= len(parts):
        return None

    target = parts[depth]
    is_final = depth == len(parts) - 1

    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if child.name == target:
                if is_final:
                    return child
                result = _search(child, parts, depth + 1)
                if result is not None:
                    return result
        elif isinstance(child, ast.ClassDef) and child.name == target:
            result = _search(child, parts, depth + 1)
            if result is not None:
                return result

    return None
