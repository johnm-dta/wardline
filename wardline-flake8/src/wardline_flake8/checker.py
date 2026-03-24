"""WardlineChecker — flake8 AST checker entry point."""

from __future__ import annotations

import ast
from typing import Iterator

from wardline_flake8.wl001 import check_wl001
from wardline_flake8.wl002 import check_wl002
from wardline_flake8.wl003 import check_wl003
from wardline_flake8.wl004 import check_wl004
from wardline_flake8.wl005 import check_wl005


class WardlineChecker:
    """Flake8 AST checker for wardline advisory rules (WL001-WL005)."""

    name = "wardline-flake8"
    version = "0.1.0"

    def __init__(self, tree: ast.Module) -> None:
        self._tree = tree

    def run(self) -> Iterator[tuple[int, int, str, type]]:
        yield from check_wl001(self._tree)
        yield from check_wl002(self._tree)
        yield from check_wl003(self._tree)
        yield from check_wl004(self._tree)
        yield from check_wl005(self._tree)
