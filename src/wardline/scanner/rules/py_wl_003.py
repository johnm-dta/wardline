"""PY-WL-003: Existence-checking as structural gate.

Detects patterns that check for the existence of a key/attribute as a
structural gate:

- ``"key" in d`` / ``key in d.keys()`` — ``in`` operator on containers
- ``"key" not in d`` — ``not in`` is still an existence check
- ``hasattr(obj, "name")`` — existence check on attributes
- ``match/case`` with ``MatchMapping`` — structural pattern on mappings
- ``match/case`` with ``MatchClass`` — structural pattern on classes
"""

from __future__ import annotations

import ast
import logging
from typing import TYPE_CHECKING

from wardline.core import matrix
from wardline.core.severity import RuleId
from wardline.manifest.scope import path_within_scope
from wardline.scanner.context import Finding
from wardline.scanner.rules.base import RuleBase, walk_skip_nested_defs

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from wardline.core.taints import TaintState

# Boundary transitions whose bodies are expected to perform existence checks
# as part of structural validation. We accept both manifest-style transition
# names and decorator-style names because tests and local tooling currently
# use both spellings.
_SUPPRESSED_BOUNDARY_TRANSITIONS = frozenset({
    "shape_validation",
    "combined_validation",
    "external_validation",
    "validates_shape",
    "validates_external",
})


_SET_CONSTRUCTOR_NAMES = frozenset({"set", "frozenset"})
_SET_OPERATORS = frozenset({ast.BitOr, ast.BitAnd, ast.Sub, ast.BitXor})


def _rhs_is_set_typed(node: ast.expr) -> bool:
    """Return True if the expression is recognisably a set/frozenset value.

    Matches set literals (``{1, 2}``), set comprehensions, set/frozenset
    constructor calls, and binary set operations (``|``, ``&``, ``-``, ``^``).
    """
    if isinstance(node, (ast.Set, ast.SetComp)):
        return True
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id in _SET_CONSTRUCTOR_NAMES:
            return True
        if isinstance(node.func, ast.Attribute) and node.func.attr in _SET_CONSTRUCTOR_NAMES:
            return True
    return isinstance(node, ast.BinOp) and type(node.op) in _SET_OPERATORS


def _annotation_is_set_type(ann: ast.expr) -> bool:
    """Return True if a type annotation references set or frozenset."""
    if isinstance(ann, ast.Name) and ann.id in _SET_CONSTRUCTOR_NAMES:
        return True
    if isinstance(ann, ast.Subscript) and isinstance(ann.value, ast.Name):
        return ann.value.id in _SET_CONSTRUCTOR_NAMES
    return False


def _iter_likely_yields_sets(node: ast.expr) -> bool:
    """Heuristic: does iterating this expression likely yield set elements?

    Matches calls like ``compute_sccs(graph)`` where the function name
    suggests it returns a collection of sets (e.g., ``_sccs``, ``_sets``).
    """
    if isinstance(node, ast.Call):
        name = _extract_call_name(node)
        if name is not None and any(s in name.lower() for s in ("scc", "_sets", "_groups")):
            return True
    return False


def _extract_call_name(call: ast.Call) -> str | None:
    """Extract the terminal function/method name from a Call node."""
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return None


# Suffixes that strongly suggest a function/method returns a set or frozenset.
_SET_RETURN_SUFFIXES = ("_names", "_set", "_keys", "_ids", "_set_names", "_name_set")


def _name_suggests_set(name: str) -> bool:
    """Return True if a function/method name suggests it returns a set."""
    lower = name.lower()
    return any(lower.endswith(suffix) for suffix in _SET_RETURN_SUFFIXES)


_STRING_NAME_SUFFIXES = ("_lower", "_upper", "_name", "_text", "_str", "_msg", "_message", "_label")


def _comparator_looks_like_string(node: ast.expr) -> bool:
    """Heuristic: does the comparator look like it holds a string value?

    When a string literal is tested with ``in`` against a variable whose
    name suggests it's a string (e.g., ``receiver_lower``, ``func_name``),
    the operation is substring containment, not key-existence checking.
    """
    name: str | None = None
    if isinstance(node, ast.Name):
        name = node.id
    elif isinstance(node, ast.Attribute):
        name = node.attr
    if name is None:
        return False
    lower = name.lower()
    return any(lower.endswith(suffix) for suffix in _STRING_NAME_SUFFIXES)


class RulePyWl003(RuleBase):
    """Detect existence-checking as structural gate patterns.

    Collects findings into ``self.findings`` during AST traversal.
    The engine reads this list after rule execution.
    """

    RULE_ID = RuleId.PY_WL_003

    def __init__(self, *, file_path: str = "") -> None:
        super().__init__()
        self._file_path = file_path

    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        """Walk the function body looking for PY-WL-003 patterns."""
        if self._is_structural_validation_boundary():
            taint = self._get_function_taint(self._current_qualname)
            logger.debug(
                "PY-WL-003 suppressed for %s (taint=%s)",
                self._current_qualname, taint,
            )
            return
        taint = self._get_function_taint(self._current_qualname)
        known_set_names = self._collect_set_variable_names(node)
        for child in walk_skip_nested_defs(node):
            if isinstance(child, ast.Compare):
                self._check_compare(child, node, taint, known_set_names)
            elif isinstance(child, ast.Call):
                self._check_hasattr(child, node, taint)
            elif isinstance(child, ast.MatchMapping):
                self._emit_finding(
                    child,
                    node,
                    "Existence check as structural gate — "
                    "structural pattern match on mapping",
                    taint,
                )
            elif isinstance(child, ast.MatchClass):
                self._emit_finding(
                    child,
                    node,
                    "Existence check as structural gate — "
                    "structural pattern match on class",
                    taint,
                )

    def _is_structural_validation_boundary(self) -> bool:
        """Return True when this function is a shape/combined validator.

        The authoritative Wardline spec suppresses PY-WL-003 inside
        declared shape-validation and combined-validation boundaries,
        where existence-checking is the purpose of the boundary body.
        """
        if self._context is None:
            return False
        return any(
            boundary.function == self._current_qualname
            and boundary.transition in _SUPPRESSED_BOUNDARY_TRANSITIONS
            and path_within_scope(self._file_path, boundary.overlay_scope)
            for boundary in self._context.boundaries
        )

    @staticmethod
    def _collect_set_variable_names(
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> frozenset[str]:
        """Pre-scan function body for local names assigned from set-typed expressions.

        Tracks names assigned from:
        - Set literals: ``s = {1, 2, 3}``
        - Set/frozenset constructors: ``s = set(items)``, ``s = frozenset(items)``
        - Set comprehensions: ``s = {x for x in items}``
        - Set operations (``|``, ``&``, ``-``, ``^``): ``s = a | b``
        - Parameter annotations containing ``set`` or ``frozenset``
        - Names that receive ``.add()`` / ``.discard()`` / ``.update()``
          method calls (implies the receiver is a set)
        - Augmented assignment with set operators: ``s |= other``

        These names represent value-classification collections, not
        mapping-key-existence targets.  ``x in my_set`` is value membership,
        not a structural gate.
        """
        set_names: set[str] = set()

        # Check parameter annotations for set/frozenset type hints
        for arg in node.args.args + node.args.kwonlyargs:
            if arg.annotation is not None and _annotation_is_set_type(arg.annotation):
                set_names.add(arg.arg)

        for child in walk_skip_nested_defs(node):
            # Direct assignment from set-typed expression
            if isinstance(child, ast.Assign):
                if _rhs_is_set_typed(child.value):
                    for target in child.targets:
                        if isinstance(target, ast.Name):
                            set_names.add(target.id)

            # Method calls that imply the receiver is a set:
            # s.add(x), s.discard(x), s.update(other)
            elif (
                isinstance(child, ast.Expr)
                and isinstance(child.value, ast.Call)
                and isinstance(child.value.func, ast.Attribute)
                and child.value.func.attr in {"add", "discard", "update", "difference_update", "intersection_update", "symmetric_difference_update"}
                and isinstance(child.value.func.value, ast.Name)
            ):
                set_names.add(child.value.func.value.id)

            # Augmented assignment with set operators: s |= other, s -= other
            elif (
                isinstance(child, ast.AugAssign)
                and type(child.op) in _SET_OPERATORS
                and isinstance(child.target, ast.Name)
            ):
                set_names.add(child.target.id)

            # For-loop targets iterating known set collections or set-returning calls:
            #   for scc in sccs  (where sccs is known set or list of sets)
            #   for item in set_items  (name suggests set content)
            elif isinstance(child, ast.For) and isinstance(child.target, ast.Name):
                iter_val = child.iter
                # Iterating a known set variable → loop var elements are set items (not sets themselves)
                # But iterating a *collection of sets* → loop var IS a set
                # We can't distinguish these at AST level, so check if the iterable
                # is a known set variable — if so, items aren't sets.
                # Instead, check if the iterable NAME suggests it's a collection of sets
                # or if the iterable was assigned from a call returning sets.
                if isinstance(iter_val, ast.Name) and iter_val.id in set_names:
                    # Iterating a set itself — items are values, not sets. Skip.
                    pass
                elif _iter_likely_yields_sets(iter_val):
                    set_names.add(child.target.id)

        # Second pass: track names assigned from calls to methods whose names
        # strongly suggest set return types. This catches patterns like
        # `annotations = self._annotation_names()` returning frozenset[str].
        for child in walk_skip_nested_defs(node):
            if not isinstance(child, ast.Assign):
                continue
            if not isinstance(child.value, ast.Call):
                continue
            call_name = _extract_call_name(child.value)
            if call_name is not None and _name_suggests_set(call_name):
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        set_names.add(target.id)

        return frozenset(set_names)

    def _check_compare(
        self,
        compare: ast.Compare,
        enclosing_func: ast.FunctionDef | ast.AsyncFunctionDef,
        taint: TaintState,
        known_set_names: frozenset[str] = frozenset(),
    ) -> None:
        """Check a Compare node for ``in`` / ``not in`` operators."""
        for op, comparator in zip(compare.ops, compare.comparators, strict=False):
            if (
                isinstance(op, (ast.In, ast.NotIn))
                and self._looks_like_existence_check(compare.left, comparator, known_set_names)
            ):
                self._emit_finding(
                    compare,
                    enclosing_func,
                    "Existence check as structural gate — "
                    "'in' operator used for key/attribute presence check",
                    taint,
                )
                return

    def _looks_like_existence_check(
        self,
        left: ast.expr,
        comparator: ast.expr,
        known_set_names: frozenset[str] = frozenset(),
    ) -> bool:
        """Heuristically distinguish key-presence checks from value membership.

        We still accept mapping-like shapes such as ``key in data`` and
        ``key in data.keys()``, but suppress obvious value-membership cases
        like ``x in [1, 2, 3]`` and ``x in values``.

        ``known_set_names`` is the set of local variable names pre-identified
        as holding set/frozenset values by ``_collect_set_variable_names``.
        """
        if self._is_obvious_value_membership(comparator):
            return False
        # Suppress membership tests against known set-typed variables.
        # ``x in my_set`` is value classification, not structural gating.
        if isinstance(comparator, ast.Name) and comparator.id in known_set_names:
            return False
        # Suppress membership tests against self.attr — these are typically
        # frozenset/set instance attributes used for classification.
        if (
            isinstance(comparator, ast.Attribute)
            and isinstance(comparator.value, ast.Name)
            and comparator.value.id == "self"
        ):
            return False
        # Suppress substring containment: "literal" in string_var where
        # the comparator name suggests it holds a string (e.g., _lower,
        # _name, _text).  This is substring search, not key existence.
        if (
            isinstance(left, ast.Constant)
            and isinstance(left.value, str)
            and _comparator_looks_like_string(comparator)
        ):
            return False
        if isinstance(comparator, ast.Call):
            return self._is_mapping_keys_call(comparator)
        if isinstance(comparator, (ast.Dict, ast.DictComp)):
            return True
        if not isinstance(comparator, (ast.Name, ast.Attribute, ast.Subscript)):
            return False
        # String/bytes literal LHS is almost always a key-existence check:
        #   "key" in data  →  existence check (fire)
        # Variable/attribute LHS against an UPPER_CASE name is almost always
        # value-membership:
        #   dto.code not in VALID_CODES  →  value membership (suppress)
        if self._is_constant_set_name(comparator):
            return False
        return True

    @staticmethod
    def _is_constant_set_name(node: ast.expr) -> bool:
        """Return True when the node looks like a constant/enum set.

        Heuristic: UPPER_CASE bare names (``VALID_CODES``, ``ALLOWED_TYPES``)
        are conventionally constant sets used for value-membership checks, not
        dicts used for key-existence checks.
        """
        if isinstance(node, ast.Name):
            return node.id.isupper()
        if isinstance(node, ast.Attribute):
            return node.attr.isupper()
        return False

    @staticmethod
    def _is_mapping_keys_call(call: ast.Call) -> bool:
        """Return True for ``obj.keys()`` calls."""
        return (
            isinstance(call.func, ast.Attribute)
            and call.func.attr == "keys"
            and not call.args
            and not call.keywords
        )

    def _is_obvious_value_membership(self, comparator: ast.expr) -> bool:
        """Return True for syntax that clearly expresses value membership."""
        if isinstance(
            comparator,
            (
                ast.List,
                ast.Tuple,
                ast.Set,
                ast.ListComp,
                ast.SetComp,
                ast.GeneratorExp,
                ast.JoinedStr,
            ),
        ):
            return True
        if isinstance(comparator, ast.Constant) and isinstance(
            comparator.value, str | bytes
        ):
            return True
        if not isinstance(comparator, ast.Call):
            return False
        if isinstance(comparator.func, ast.Name) and comparator.func.id in {
            "list",
            "tuple",
            "set",
            "frozenset",
            "sorted",
        }:
            return True
        return (
            isinstance(comparator.func, ast.Attribute)
            and comparator.func.attr in {"values", "items", "split"}
        )

    def _check_hasattr(
        self,
        call: ast.Call,
        enclosing_func: ast.FunctionDef | ast.AsyncFunctionDef,
        taint: TaintState,
    ) -> None:
        """Check a Call node for ``hasattr(obj, name)``."""
        if isinstance(call.func, ast.Name) and call.func.id == "hasattr":
            self._emit_finding(
                call,
                enclosing_func,
                "Existence check as structural gate — "
                "hasattr() used for attribute presence check",
                taint,
            )

    def _emit_finding(
        self,
        node: ast.AST,
        enclosing_func: ast.FunctionDef | ast.AsyncFunctionDef,
        message: str,
        taint: TaintState,
    ) -> None:
        """Emit a PY-WL-003 finding."""
        cell = matrix.lookup(RuleId.PY_WL_003, taint)
        self.findings.append(
            Finding(
                rule_id=RuleId.PY_WL_003,
                file_path=self._file_path,
                line=getattr(node, "lineno", 0),
                col=getattr(node, "col_offset", 0),
                end_line=getattr(node, "end_lineno", None),
                end_col=getattr(node, "end_col_offset", None),
                message=message,
                severity=cell.severity,
                exceptionability=cell.exceptionability,
                taint_state=taint,
                analysis_level=1,
                source_snippet=None,
                qualname=self._current_qualname,
            )
        )
