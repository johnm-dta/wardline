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
import logging
from abc import ABC, abstractmethod
from collections import deque
from typing import TYPE_CHECKING, ClassVar, final

from wardline.core.taints import TaintState

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from wardline.core.severity import RuleId
    from wardline.scanner.context import Finding, ScanContext

_GUARDED_METHODS = frozenset({"visit_FunctionDef", "visit_AsyncFunctionDef"})


def walk_skip_nested_defs(node: ast.AST) -> Iterator[ast.AST]:
    """Like ``ast.walk`` but skip nested FunctionDef/AsyncFunctionDef bodies.

    The root *node* is always yielded. Child nodes that are
    ``FunctionDef`` or ``AsyncFunctionDef`` (and are not the root) are
    skipped entirely — the base class ``generic_visit`` handles those
    separately, so descending here would cause duplicate findings.
    """
    todo: deque[ast.AST] = deque([node])
    while todo:
        current = todo.popleft()
        yield current
        for child in ast.iter_child_nodes(current):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child is not node:
                continue
            todo.append(child)


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
        super().__init__()
        self.findings: list[Finding] = []
        self._file_path: str = ""
        self._context: ScanContext | None = None
        self._scope_stack: list[str] = []
        self._current_qualname: str = ""

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

    def set_context(self, ctx: ScanContext | None) -> None:
        """Set (or clear) the per-file scan context.

        Also syncs ``_file_path`` and resets scope tracking state so
        ScanContext is the single authoritative source of per-file state.
        Resetting the scope stack here ensures that a crash during a
        previous file's traversal cannot corrupt qualnames for this file.
        """
        self._context = ctx
        self._file_path = ctx.file_path if ctx is not None else ""
        self._scope_stack.clear()
        self._current_qualname = ""

    def _get_function_taint(self, qualname: str) -> TaintState:
        """Look up the taint state for *qualname* in the current context.

        Returns ``UNKNOWN_RAW`` when no context is set or the qualname
        is not present in the taint map.
        """
        if self._context is None:
            return TaintState.UNKNOWN_RAW
        taint = self._context.function_level_taint_map.get(qualname)
        if taint is None:
            logger.debug(
                "Taint map miss for qualname %r in %s",
                qualname, self._file_path,
            )
            return TaintState.UNKNOWN_RAW
        return taint

    def _dispatch(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef, *, is_async: bool
    ) -> None:
        """Dispatch to visit_function, then recurse into nested defs.

        The scope stack push happens before visit_function so that
        ``self._current_qualname`` is correct during rule execution.
        The pop happens AFTER generic_visit so that nested functions
        see the enclosing function on the scope stack.  try/finally
        guarantees the pop even if visit_function raises.
        """
        self._current_qualname = ".".join([*self._scope_stack, node.name])
        self._scope_stack.append(node.name)
        try:
            self.visit_function(node, is_async=is_async)
            self.generic_visit(node)
        finally:
            self._scope_stack.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Track class scope for qualname construction."""
        self._scope_stack.append(node.name)
        try:
            self.generic_visit(node)
        finally:
            self._scope_stack.pop()

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
