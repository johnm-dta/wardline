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
        for child in walk_skip_nested_defs(node):
            if isinstance(child, ast.Compare):
                self._check_compare(child, node, taint)
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

    def _check_compare(
        self,
        compare: ast.Compare,
        enclosing_func: ast.FunctionDef | ast.AsyncFunctionDef,
        taint: TaintState,
    ) -> None:
        """Check a Compare node for ``in`` / ``not in`` operators."""
        for op, comparator in zip(compare.ops, compare.comparators, strict=False):
            if (
                isinstance(op, (ast.In, ast.NotIn))
                and self._looks_like_existence_check(compare.left, comparator)
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
    ) -> bool:
        """Heuristically distinguish key-presence checks from value membership.

        We still accept mapping-like shapes such as ``key in data`` and
        ``key in data.keys()``, but suppress obvious value-membership cases
        like ``x in [1, 2, 3]`` and ``x in values``.
        """
        if self._is_obvious_value_membership(comparator):
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
