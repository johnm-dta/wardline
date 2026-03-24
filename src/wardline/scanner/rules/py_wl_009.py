"""PY-WL-009: Semantic boundary without prior shape validation.

Detects declared semantic-validation boundaries whose semantic checks
have no prior structural validation evidence within the boundary body.
Combined validation boundaries are excluded because they satisfy the
ordering requirement internally by definition.
"""

from __future__ import annotations

import ast

from wardline.core import matrix
from wardline.core.severity import RuleId
from wardline.manifest.scope import path_within_scope
from wardline.scanner.context import Finding
from wardline.scanner.rules.base import RuleBase, walk_skip_nested_defs

_SEMANTIC_BOUNDARY_TRANSITIONS = frozenset({"semantic_validation"})
_COMBINED_BOUNDARY_TRANSITIONS = frozenset({
    "combined_validation",
    "external_validation",
})
_SEMANTIC_BOUNDARY_DECORATORS = frozenset({"validates_semantic"})
_COMBINED_BOUNDARY_DECORATORS = frozenset({"validates_external"})

# Function name fragments that indicate shape validation.
_SHAPE_VALIDATION_NAMES = frozenset({
    "validate_schema",
    "check_schema",
    "verify_schema",
    "validate_shape",
    "check_shape",
    "verify_shape",
    "validate_structure",
    "check_structure",
    "verify_structure",
})

# Substrings in function names that suggest shape validation.
_SHAPE_VALIDATION_SUBSTRINGS = ("schema", "shape", "structure")

# Generic method names that become shape validators when the receiver
# (object they're called on) has a schema-related name.
_SCHEMA_QUALIFIED_METHODS = frozenset({"validate", "is_valid"})


def _has_shape_check_before(
    stmts: list[ast.stmt],
    *,
    stop_line: int,
) -> bool:
    """Check if any statement before *stop_line* is a shape validation.

    Shape validations include:
    - isinstance(...) calls
    - hasattr(...) calls
    - ``"key" in data`` / ``key in data`` comparisons
    - Calls to functions with shape-validation names
    """
    for node in walk_skip_nested_defs(ast.Module(body=stmts, type_ignores=[])):
        if getattr(node, "lineno", 0) >= stop_line:
            continue
        if isinstance(node, ast.Call):
            if _is_shape_validation_call(node):
                return True
        elif isinstance(node, ast.Compare) and _is_membership_test(node):
            return True
    return False


def _decorator_name(decorator: ast.expr) -> str | None:
    """Return the terminal decorator name for ``@name`` and ``@pkg.name``."""
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    return None


def _has_direct_decorator(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    names: frozenset[str],
) -> bool:
    """Check whether the function has any decorator whose terminal name matches."""
    return any(
        _decorator_name(decorator) in names
        for decorator in node.decorator_list
    )


def _is_shape_validation_call(call: ast.Call) -> bool:
    """Check if a call is isinstance, hasattr, or a shape-validation function.

    Recognised patterns:
    - ``isinstance(x, T)`` / ``hasattr(x, "a")``
    - Bare calls whose name matches ``_SHAPE_VALIDATION_NAMES`` or contains
      a ``_SHAPE_VALIDATION_SUBSTRINGS`` fragment.
    - Method calls ``obj.method(...)`` where *method* matches the above.
    - Schema-qualified calls: ``jsonschema.validate()``, ``schema.is_valid()``
      — a generic method name in ``_SCHEMA_QUALIFIED_METHODS`` called on a
      receiver whose name contains a schema-related substring.
    """
    if isinstance(call.func, ast.Name):
        name = call.func.id
        if name in ("isinstance", "hasattr"):
            return True
        if name in _SHAPE_VALIDATION_NAMES:
            return True
        for sub in _SHAPE_VALIDATION_SUBSTRINGS:
            if sub in name.lower():
                return True
    if isinstance(call.func, ast.Attribute):
        attr = call.func.attr
        if attr in _SHAPE_VALIDATION_NAMES:
            return True
        for sub in _SHAPE_VALIDATION_SUBSTRINGS:
            if sub in attr.lower():
                return True
        # Schema-qualified: receiver.validate() where receiver name
        # contains a schema-related term (e.g. jsonschema.validate).
        if attr in _SCHEMA_QUALIFIED_METHODS:
            receiver = _receiver_name(call.func.value)
            if receiver:
                receiver_lower = receiver.lower()
                for sub in _SHAPE_VALIDATION_SUBSTRINGS:
                    if sub in receiver_lower:
                        return True
    return False


def _receiver_name(node: ast.expr) -> str | None:
    """Extract a dotted name from an expression for receiver matching.

    Returns the name for ``ast.Name`` (e.g. ``"jsonschema"``) or the
    full dotted chain for ``ast.Attribute`` (e.g. ``"json_schema"``).
    Returns ``None`` for complex expressions.
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _receiver_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _is_membership_test(compare: ast.Compare) -> bool:
    """Check if a Compare node is ``x in y`` or ``x not in y``."""
    return any(isinstance(op, (ast.In, ast.NotIn)) for op in compare.ops)


def _has_subscript_access(node: ast.AST) -> bool:
    """Check if node contains a subscript access (``data["key"]``).

    Only matches ``ast.Subscript`` — NOT ``ast.Attribute``.  Attribute
    access (``obj.attr``) is shape-guaranteed by the type system: the
    class definition IS the shape declaration.  Subscript access on
    dicts/lists has no such guarantee and needs explicit shape validation.
    """
    return any(isinstance(child, ast.Subscript) for child in ast.walk(node))


def _test_contains_shape_check(test: ast.expr) -> bool:
    """Check if a conditional test already contains an inline shape validation.

    When a condition like ``isinstance(x, T) and x.attr > 0`` is found,
    the isinstance IS the shape guard for the attribute access in the same
    expression.  These should not be classified as unguarded semantic checks.
    """
    for child in ast.walk(test):
        if isinstance(child, ast.Call) and _is_shape_validation_call(child):
            return True
        if isinstance(child, ast.Compare) and _is_membership_test(child):
            return True
    return False


def _get_semantic_check_nodes(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[ast.AST]:
    """Find if/assert nodes that perform semantic checks on subscript data.

    A semantic check is an if-test or assert that accesses data via
    subscript (``data["key"]``) and compares or tests a value — business
    logic validation on the data's content rather than its shape.

    Pure attribute access (``obj.attr``) is excluded — the type system
    guarantees attributes declared by the class definition.  Only
    subscript access (``data["key"]``) indicates potentially unvalidated
    shape.

    Conditions that already contain an inline shape check (isinstance,
    hasattr, membership test) are excluded — the shape guard in the
    condition itself covers the subscript access.
    """
    results: list[ast.AST] = []
    for child in walk_skip_nested_defs(node):
        if not isinstance(child, (ast.If, ast.Assert)):
            continue
        if not _has_subscript_access(child.test):
            continue
        if _test_contains_shape_check(child.test):
            continue
        results.append(child)
    return results


class RulePyWl009(RuleBase):
    """Detect semantic validation without prior shape validation.

    Collects findings into ``self.findings`` during AST traversal.
    The engine reads this list after rule execution.
    """

    RULE_ID = RuleId.PY_WL_009

    def __init__(self, *, file_path: str = "") -> None:
        super().__init__()
        self._file_path = file_path

    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        """Walk semantic-validation boundaries for missing shape-validation evidence."""
        if self._is_combined_boundary(node):
            return
        if not self._is_semantic_boundary(node):
            return
        semantic_checks = _get_semantic_check_nodes(node)
        if not semantic_checks:
            return

        # For each semantic check, see if there's a shape check before it
        for check in semantic_checks:
            check_line = getattr(check, "lineno", 0)
            if not _has_shape_check_before(node.body, stop_line=check_line):
                self._emit_finding(check)

    def _is_semantic_boundary(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> bool:
        """Return True when this function is a declared semantic validator."""
        if self._context is not None:
            for boundary in self._context.boundaries:
                if (
                    boundary.function == self._current_qualname
                    and boundary.transition in _SEMANTIC_BOUNDARY_TRANSITIONS
                    and path_within_scope(self._file_path, boundary.overlay_scope)
                ):
                    return True
        return _has_direct_decorator(node, _SEMANTIC_BOUNDARY_DECORATORS)

    def _is_combined_boundary(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> bool:
        """Return True when this function is a declared combined validator."""
        if self._context is not None:
            for boundary in self._context.boundaries:
                if (
                    boundary.function == self._current_qualname
                    and boundary.transition in _COMBINED_BOUNDARY_TRANSITIONS
                    and path_within_scope(self._file_path, boundary.overlay_scope)
                ):
                    return True
        return _has_direct_decorator(node, _COMBINED_BOUNDARY_DECORATORS)

    def _emit_finding(self, node: ast.AST) -> None:
        """Emit a PY-WL-009 finding."""
        taint = self._get_function_taint(self._current_qualname)
        cell = matrix.lookup(self.RULE_ID, taint)
        self.findings.append(
            Finding(
                rule_id=RuleId.PY_WL_009,
                file_path=self._file_path,
                line=getattr(node, "lineno", 0),
                col=getattr(node, "col_offset", 0),
                end_line=getattr(node, "end_lineno", None),
                end_col=getattr(node, "end_col_offset", None),
                message=(
                    "Semantic validation without prior shape validation — "
                    "business logic check on data that has not been "
                    "structurally validated"
                ),
                severity=cell.severity,
                exceptionability=cell.exceptionability,
                taint_state=taint,
                analysis_level=1,
                source_snippet=None,
                qualname=self._current_qualname,
            )
        )
