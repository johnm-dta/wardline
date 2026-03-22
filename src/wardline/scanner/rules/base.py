"""RuleBase — abstract base class for all wardline scanner rules.

All rules subclass RuleBase and implement ``visit_function``. The
``visit_FunctionDef`` and ``visit_AsyncFunctionDef`` methods are
``@typing.final`` and delegate to ``visit_function`` — subclasses
must not override them. ``__init_subclass__`` enforces this at
class definition time (runtime), ``@typing.final`` enforces it
statically (mypy).
"""

from __future__ import annotations

import ast
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar, final

if TYPE_CHECKING:
    from wardline.core.severity import RuleId
    from wardline.scanner.context import Finding

_GUARDED_METHODS = frozenset({"visit_FunctionDef", "visit_AsyncFunctionDef"})


class RuleBase(ast.NodeVisitor, ABC):
    """Abstract base for all wardline scanner rules.

    Concrete rules must:
    - Subclass RuleBase directly
    - Set ``RULE_ID`` class variable to the canonical ``RuleId``
    - Implement ``visit_function(node, is_async)``
    - NOT override ``visit_FunctionDef`` or ``visit_AsyncFunctionDef``
    """

    RULE_ID: ClassVar[RuleId]

    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self._file_path: str = ""

    def __init_subclass__(cls, **kwargs: object) -> None:
        # Call super BEFORE our check — required for cooperative MRO
        super().__init_subclass__(**kwargs)

        for method_name in _GUARDED_METHODS:
            if method_name in cls.__dict__:
                raise TypeError(
                    f"{cls.__name__} must not override {method_name}. "
                    f"Implement visit_function() instead."
                )

    @final
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Dispatch sync function to visit_function. Do not override."""
        self._dispatch(node, is_async=False)

    @final
    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Dispatch async function to visit_function. Do not override."""
        self._dispatch(node, is_async=True)

    def _dispatch(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef, *, is_async: bool
    ) -> None:
        """Dispatch to visit_function, then continue generic_visit."""
        self.visit_function(node, is_async=is_async)
        self.generic_visit(node)

    @abstractmethod
    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        """Visit a function definition. Implement in subclasses.

        Findings should be appended to an instance-level collection.
        The ``is_async`` flag distinguishes sync from async functions
        without requiring isinstance checks in every rule.
        """
        ...
