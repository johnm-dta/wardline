"""Tests for PY-WL-007: Runtime type-checking on internal data."""

from __future__ import annotations

from wardline.core.severity import RuleId, Severity
from wardline.core.taints import TaintState
from wardline.scanner.context import ScanContext
from wardline.scanner.rules.py_wl_007 import RulePyWl007

from .conftest import parse_function_source, parse_module_source


def _run_rule(source: str) -> RulePyWl007:
    """Parse source inside a function and run PY-WL-007."""
    tree = parse_function_source(source)
    rule = RulePyWl007(file_path="test.py")
    rule.visit(tree)
    return rule


def _run_rule_module(source: str) -> RulePyWl007:
    """Parse raw module source and run PY-WL-007."""
    tree = parse_module_source(source)
    rule = RulePyWl007(file_path="test.py")
    rule.visit(tree)
    return rule


def _run_rule_with_taint(source: str, taint: TaintState) -> RulePyWl007:
    """Parse source inside a function, set taint, run PY-WL-007."""
    tree = parse_function_source(source)
    rule = RulePyWl007(file_path="test.py")
    ctx = ScanContext(
        file_path="test.py",
        function_level_taint_map={"target": taint},
    )
    rule.set_context(ctx)
    rule.visit(tree)
    return rule


# -- Positive: isinstance fires -------------------------------------------


class TestIsinstance:
    """isinstance() calls fire PY-WL-007."""

    def test_isinstance_dict_fires(self) -> None:
        rule = _run_rule("isinstance(record, dict)\n")

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_007
        assert "isinstance" in rule.findings[0].message

    def test_isinstance_str_fires(self) -> None:
        rule = _run_rule("isinstance(value, str)\n")

        assert len(rule.findings) == 1

    def test_isinstance_tuple_types_fires(self) -> None:
        rule = _run_rule("isinstance(data, (dict, list))\n")

        assert len(rule.findings) == 1

    def test_isinstance_in_if_fires(self) -> None:
        rule = _run_rule(
            """\
if isinstance(record, dict):
    handle_dict(record)
"""
        )

        assert len(rule.findings) == 1

    def test_isinstance_in_assert_fires(self) -> None:
        rule = _run_rule("assert isinstance(x, int)\n")

        assert len(rule.findings) == 1

    def test_multiple_isinstance_fires(self) -> None:
        rule = _run_rule(
            """\
isinstance(a, int)
isinstance(b, str)
"""
        )

        assert len(rule.findings) == 2


# -- Positive: type() comparison fires ------------------------------------


class TestTypeComparison:
    """type(x) == T and type(x) is T fire PY-WL-007."""

    def test_type_eq_fires(self) -> None:
        rule = _run_rule("type(x) == dict\n")

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_007
        assert "type()" in rule.findings[0].message

    def test_type_is_fires(self) -> None:
        rule = _run_rule("type(x) is int\n")

        assert len(rule.findings) == 1

    def test_type_not_eq_fires(self) -> None:
        rule = _run_rule("type(x) != str\n")

        assert len(rule.findings) == 1

    def test_type_is_not_fires(self) -> None:
        rule = _run_rule("type(x) is not list\n")

        assert len(rule.findings) == 1

    def test_type_in_if_fires(self) -> None:
        rule = _run_rule(
            """\
if type(record) == dict:
    process(record)
"""
        )

        assert len(rule.findings) == 1


# -- Positive: async function ---------------------------------------------


class TestAsyncFunction:
    """Type checks in async functions fire PY-WL-007."""

    def test_isinstance_in_async_fires(self) -> None:
        rule = _run_rule_module(
            """\
async def target():
    if isinstance(data, dict):
        await process(data)
"""
        )

        assert len(rule.findings) == 1


# -- Taint-gated: SUPPRESS for external/unknown raw -----------------------


class TestTaintGating:
    """PY-WL-007 severity depends on taint state."""

    def test_audit_trail_is_error(self) -> None:
        rule = _run_rule_with_taint(
            "isinstance(x, dict)\n",
            TaintState.INTEGRAL,
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].severity == Severity.ERROR

    def test_external_raw_is_suppress(self) -> None:
        rule = _run_rule_with_taint(
            "isinstance(x, dict)\n",
            TaintState.EXTERNAL_RAW,
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].severity == Severity.SUPPRESS

    def test_unknown_raw_is_suppress(self) -> None:
        rule = _run_rule_with_taint(
            "isinstance(x, dict)\n",
            TaintState.UNKNOWN_RAW,
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].severity == Severity.SUPPRESS

    def test_pipeline_is_warning(self) -> None:
        rule = _run_rule_with_taint(
            "isinstance(x, dict)\n",
            TaintState.ASSURED,
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].severity == Severity.WARNING

    def test_mixed_raw_is_warning(self) -> None:
        rule = _run_rule_with_taint(
            "isinstance(x, dict)\n",
            TaintState.MIXED_RAW,
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].severity == Severity.WARNING


# -- Negative: no type checks ---------------------------------------------


class TestNoFalsePositives:
    """Patterns that should NOT fire PY-WL-007."""

    def test_regular_function_call_silent(self) -> None:
        rule = _run_rule("len(data)\n")

        assert len(rule.findings) == 0

    def test_method_call_silent(self) -> None:
        rule = _run_rule("data.items()\n")

        assert len(rule.findings) == 0

    def test_type_call_alone_silent(self) -> None:
        """type(x) without comparison does NOT fire."""
        rule = _run_rule("t = type(x)\n")

        assert len(rule.findings) == 0

    def test_comparison_without_type_silent(self) -> None:
        rule = _run_rule("x == dict\n")

        assert len(rule.findings) == 0

    def test_empty_function_silent(self) -> None:
        rule = _run_rule("pass\n")

        assert len(rule.findings) == 0


# -- Edge: nested functions ------------------------------------------------


class TestNestedFunctions:
    """Type checks in nested functions produce separate findings."""

    def test_nested_isinstance_fires_separately(self) -> None:
        rule = _run_rule_module(
            """\
def outer():
    isinstance(a, int)

    def inner():
        isinstance(b, str)
"""
        )

        assert len(rule.findings) == 2


# -- Suppression: AST node type dispatch -----------------------------------


class TestAstTypeDispatch:
    """isinstance(node, ast.SomeType) is structural dispatch, not a boundary smell."""

    def test_isinstance_ast_type_silent(self) -> None:
        """isinstance(node, ast.Assign) — dispatching on AST node type."""
        rule = _run_rule(
            """\
if isinstance(node, ast.Assign):
    handle_assign(node)
"""
        )

        assert len(rule.findings) == 0

    def test_isinstance_ast_tuple_silent(self) -> None:
        """isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))."""
        rule = _run_rule(
            """\
if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
    skip()
"""
        )

        assert len(rule.findings) == 0

    def test_isinstance_non_ast_still_fires(self) -> None:
        """isinstance(x, dict) — not AST dispatch, still fires."""
        rule = _run_rule("isinstance(data, dict)\n")

        assert len(rule.findings) == 1

    def test_isinstance_ast_bare_name_still_fires(self) -> None:
        """isinstance(x, Name) — unqualified, could be anything, still fires."""
        rule = _run_rule("isinstance(node, Name)\n")

        assert len(rule.findings) == 1


# -- Suppression: dunder protocol -----------------------------------------


class TestDunderProtocol:
    """isinstance in __eq__/__ne__/etc returning NotImplemented is protocol."""

    def test_isinstance_in_eq_returning_not_implemented_silent(self) -> None:
        rule = _run_rule_module(
            """\
class Foo:
    def __eq__(self, other):
        if not isinstance(other, Foo):
            return NotImplemented
        return self.x == other.x
"""
        )

        assert len(rule.findings) == 0

    def test_isinstance_in_ne_returning_not_implemented_silent(self) -> None:
        rule = _run_rule_module(
            """\
class Bar:
    def __ne__(self, other):
        if not isinstance(other, Bar):
            return NotImplemented
        return self.x != other.x
"""
        )

        assert len(rule.findings) == 0

    def test_isinstance_in_eq_without_not_implemented_fires(self) -> None:
        """isinstance in __eq__ that doesn't return NotImplemented still fires."""
        rule = _run_rule_module(
            """\
class Baz:
    def __eq__(self, other):
        if isinstance(other, dict):
            return self.data == other
        return False
"""
        )

        assert len(rule.findings) == 1


# -- Suppression: frozen dataclass __post_init__ ---------------------------


class TestPostInitFreezing:
    """isinstance in __post_init__ for defensive freezing is a construction pattern."""

    def test_isinstance_in_post_init_with_freeze_silent(self) -> None:
        rule = _run_rule_module(
            """\
class Config:
    def __post_init__(self):
        if isinstance(self.data, dict):
            object.__setattr__(self, "data", MappingProxyType(self.data))
"""
        )

        assert len(rule.findings) == 0

    def test_isinstance_in_post_init_without_freeze_fires(self) -> None:
        """isinstance in __post_init__ not followed by freezing still fires."""
        rule = _run_rule_module(
            """\
class Config:
    def __post_init__(self):
        if isinstance(self.data, dict):
            self.process()
"""
        )

        assert len(rule.findings) == 1


# -- Suppression: declared boundary function -------------------------------


def _run_rule_with_boundary(
    source: str, qualname: str = "target", transition: str = "validates_shape",
) -> RulePyWl007:
    """Parse source, set up a boundary declaration, and run PY-WL-007."""
    from wardline.manifest.models import BoundaryEntry

    tree = parse_function_source(source)
    boundary = BoundaryEntry(function=qualname, transition=transition)
    ctx = ScanContext(
        file_path="test.py",
        function_level_taint_map={qualname: TaintState.GUARDED},
        boundaries=(boundary,),
    )
    rule = RulePyWl007(file_path="test.py")
    rule.set_context(ctx)
    rule.visit(tree)
    return rule


class TestDeclaredBoundary:
    """isinstance in a declared boundary function is its stated job."""

    def test_isinstance_in_declared_boundary_silent(self) -> None:
        """Function with @validates_shape — isinstance is the contract."""
        rule = _run_rule_with_boundary(
            """\
if not isinstance(data, dict):
    raise TypeError("expected dict")
"""
        )

        assert len(rule.findings) == 0

    def test_isinstance_in_declared_boundary_no_raise_still_silent(self) -> None:
        """Declared boundary suppresses isinstance regardless of raise pattern."""
        rule = _run_rule_with_boundary(
            """\
if isinstance(data, dict):
    process_dict(data)
else:
    process_other(data)
"""
        )

        assert len(rule.findings) == 0

    def test_isinstance_without_boundary_declaration_fires(self) -> None:
        """Same code without boundary declaration still fires."""
        rule = _run_rule(
            """\
if not isinstance(data, dict):
    raise TypeError("expected dict")
"""
        )

        assert len(rule.findings) == 1

    def test_isinstance_external_boundary_silent(self) -> None:
        """@external_boundary — isinstance at ingress is correct."""
        rule = _run_rule_with_boundary(
            """\
if not isinstance(payload, dict):
    raise ValueError("bad payload")
""",
            transition="external_boundary",
        )

        assert len(rule.findings) == 0
