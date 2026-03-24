"""Shared test helpers for wardline-flake8 tests."""

from __future__ import annotations

import ast
import sys
import textwrap
from typing import Callable, Iterator

import pytest

# Ensure the tests directory is on sys.path so helpers can be imported
sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent))


def parse_and_check(
    source: str,
    check_fn: Callable[[ast.Module], Iterator[tuple[int, int, str, type]]],
) -> list[tuple[int, int, str]]:
    """Parse source code and run a check function, returning (line, col, msg) triples."""
    source = textwrap.dedent(source)
    tree = ast.parse(source)
    return [(line, col, msg) for line, col, msg, _ in check_fn(tree)]
