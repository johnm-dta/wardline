"""PY-WL-007: Runtime type-checking on internal data.

Detects ``isinstance()`` and ``type() ==``/``type() is`` checks that
indicate runtime type-checking on data that should be statically typed.
In a tier model, internal data (Tier 1-2) should have known types —
runtime type checks suggest a trust boundary violation.

Taint-gated: the severity matrix shows SUPPRESS for EXTERNAL_RAW and
UNKNOWN_RAW (where type checks on untrusted data are expected), and
escalating severity for internal taint states.

Suppressed patterns (not false negatives — structurally different intent):
- AST node type dispatch: ``isinstance(node, ast.Assign)`` is structural
  dispatch on a tagged union, not evidence of untrusted data.
- Dunder protocol: ``isinstance(other, Cls)`` in ``__eq__`` returning
  ``NotImplemented`` is required by Python's data model.
- Frozen dataclass construction: ``isinstance(self.x, dict)`` in
  ``__post_init__`` followed by ``object.__setattr__`` is a defensive
  freezing pattern.
"""

from __future__ import annotations

import ast

from wardline.core.severity import RuleId
from wardline.scanner.rules.base import RuleBase, walk_skip_nested_defs

# Dunder comparison methods where isinstance + NotImplemented is protocol.
_COMPARISON_DUNDERS = frozenset({
    "__eq__", "__ne__", "__lt__", "__le__", "__gt__", "__ge__",
})


def _is_ast_qualified_type(node: ast.expr) -> bool:
    """Check if a type argument is ``ast.SomeType`` (qualified AST node type).

    Matches ``ast.X`` where ``ast`` is the receiver. Unqualified names
    like ``Name`` are not matched — they could be anything.
    """
    if isinstance(node, ast.Attribute):
        return isinstance(node.value, ast.Name) and node.value.id == "ast"
    return False


def _isinstance_has_ast_type(call: ast.Call) -> bool:
    """Check if an isinstance() call uses AST node types.

    Handles both single type ``isinstance(x, ast.Name)`` and tuples
    ``isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef))``.
    """
    if len(call.args) < 2:
        return False
    type_arg = call.args[1]
    if _is_ast_qualified_type(type_arg):
        return True
    # isinstance(x, (ast.A, ast.B, ...)) — all elements must be ast.*
    if isinstance(type_arg, ast.Tuple) and type_arg.elts:
        return all(_is_ast_qualified_type(elt) for elt in type_arg.elts)
    return False


def _function_returns_not_implemented(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Check if a function body contains ``return NotImplemented``."""
    for child in ast.walk(node):
        if (
            isinstance(child, ast.Return)
            and child.value is not None
            and isinstance(child.value, ast.Name)
            and child.value.id == "NotImplemented"
        ):
            return True
    return False


def _body_has_object_setattr(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Check if function body contains ``object.__setattr__(self, ...)``."""
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        func = child.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "__setattr__"
            and isinstance(func.value, ast.Name)
            and func.value.id == "object"
        ):
            return True
    return False


class RulePyWl007(RuleBase):
    """Detect runtime type-checking on internal data.

    Collects findings into ``self.findings`` during AST traversal.
    The engine reads this list after rule execution.
    """

    RULE_ID = RuleId.PY_WL_007

    def __init__(self, *, file_path: str = "") -> None:
        super().__init__()
        self._file_path = file_path

    def _has_declared_boundary(self) -> bool:
        """Check if the current function has a declared boundary transition.

        A declared boundary means the function is explicitly decorated
        with a wardline boundary decorator (e.g. ``@validates_shape``,
        ``@external_boundary``).  In such functions, isinstance is the
        *implementation* of the declared contract — it's the correct
        security primitive because MRO identity cannot be spoofed via
        duck typing.
        """
        if self._context is None:
            return False
        qualname = self._current_qualname
        return any(b.function == qualname for b in self._context.boundaries)

    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        """Walk function body for isinstance/type checks."""
        # Pre-compute function-level suppression flags once.
        is_dunder_cmp = (
            node.name in _COMPARISON_DUNDERS
            and _function_returns_not_implemented(node)
        )
        is_post_init_freeze = (
            node.name == "__post_init__"
            and _body_has_object_setattr(node)
        )
        is_declared_boundary = self._has_declared_boundary()

        for child in walk_skip_nested_defs(node):
            if isinstance(child, ast.Call):
                self._check_isinstance(
                    child, is_dunder_cmp, is_post_init_freeze, is_declared_boundary,
                )
            elif isinstance(child, ast.Compare):
                self._check_type_compare(child)

    def _check_isinstance(
        self,
        call: ast.Call,
        is_dunder_cmp: bool,
        is_post_init_freeze: bool,
        is_declared_boundary: bool,
    ) -> None:
        """Check for isinstance(obj, type) calls."""
        if not (isinstance(call.func, ast.Name) and call.func.id == "isinstance"):
            return

        # Suppress: AST node type dispatch (tagged union, not trust boundary).
        if _isinstance_has_ast_type(call):
            return

        # Suppress: dunder comparison protocol (isinstance + NotImplemented).
        if is_dunder_cmp:
            return

        # Suppress: frozen dataclass construction pattern.
        if is_post_init_freeze:
            return

        # Suppress: declared boundary function — isinstance is the
        # implementation of a wardline-decorated boundary contract.
        if is_declared_boundary:
            return

        self._emit_matrix_finding(
            call,
            "Runtime type-checking — isinstance() suggests "
            "unknown type at a trust boundary",
        )

    def _check_type_compare(self, compare: ast.Compare) -> None:
        """Check for ``type(x) == T`` or ``type(x) is T`` patterns."""
        # Left side must be type(...)
        if not self._is_type_call(compare.left):
            return
        for op in compare.ops:
            if isinstance(op, (ast.Eq, ast.NotEq, ast.Is, ast.IsNot)):
                self._emit_matrix_finding(
                    compare,
                    "Runtime type-checking — type() comparison suggests "
                    "unknown type at a trust boundary",
                )
                return

    @staticmethod
    def _is_type_call(node: ast.expr) -> bool:
        """Check if node is a ``type(...)`` call."""
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "type"
        )

