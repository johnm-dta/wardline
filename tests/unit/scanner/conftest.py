"""Shared fixtures for scanner rule tests.

Pattern: use ``ast.parse()`` on inline triple-quoted source strings.
Rules operate on AST nodes within function bodies, so fixtures wrap
test code in a function definition with a synthetic import preamble.
"""

from __future__ import annotations

import ast
import textwrap


def parse_function_source(source: str, *, name: str = "target") -> ast.Module:
    """Parse source code wrapped in a function definition.

    The source is dedented and placed inside ``def target(): ...``.
    Returns the full module AST.
    """
    body = textwrap.indent(textwrap.dedent(source), "    ")
    full = f"def {name}():\n{body}"
    return ast.parse(full)


def parse_module_source(source: str) -> ast.Module:
    """Parse raw module-level source code."""
    return ast.parse(textwrap.dedent(source))
