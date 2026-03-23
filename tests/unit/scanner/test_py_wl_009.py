"""Tests for PY-WL-009: Semantic validation without prior shape validation."""

from __future__ import annotations

from wardline.core.severity import RuleId, Severity
from wardline.scanner.rules.py_wl_009 import RulePyWl009

from .conftest import parse_function_source, parse_module_source


def _run_rule(source: str) -> RulePyWl009:
    """Parse source inside a function and run PY-WL-009."""
    tree = parse_function_source(source)
    rule = RulePyWl009(file_path="test.py")
    rule.visit(tree)
    return rule


def _run_rule_module(source: str) -> RulePyWl009:
    """Parse raw module source and run PY-WL-009."""
    tree = parse_module_source(source)
    rule = RulePyWl009(file_path="test.py")
    rule.visit(tree)
    return rule


# -- Positive: semantic check without shape validation ---------------------


class TestSemanticWithoutShape:
    """Semantic checks on data without prior shape checks fire PY-WL-009."""

    def test_subscript_in_if_no_shape_check_fires(self) -> None:
        rule = _run_rule(
            """\
if data["amount"] > MAX_AMOUNT:
    raise ValueError("too large")
"""
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_009
        assert rule.findings[0].severity == Severity.ERROR

    def test_subscript_comparison_no_shape_fires(self) -> None:
        rule = _run_rule(
            """\
if record["status"] == "active":
    process(record)
"""
        )

        assert len(rule.findings) == 1

    def test_nested_subscript_fires(self) -> None:
        rule = _run_rule(
            """\
if data["user"]["role"] == "admin":
    grant_access()
"""
        )

        assert len(rule.findings) == 1

    def test_assert_with_subscript_fires(self) -> None:
        rule = _run_rule(
            """\
assert data["count"] >= 0
"""
        )

        assert len(rule.findings) == 1

    def test_multiple_semantic_checks_fire(self) -> None:
        rule = _run_rule(
            """\
if data["amount"] > 100:
    flag_large()
if data["status"] == "pending":
    process_pending()
"""
        )

        assert len(rule.findings) == 2

    def test_subscript_in_boolean_condition_fires(self) -> None:
        rule = _run_rule(
            """\
if data["enabled"] and data["count"] > 0:
    process()
"""
        )

        assert len(rule.findings) == 1


# -- Negative: shape validation precedes semantic check --------------------


class TestShapeBeforeSemantic:
    """Shape checks before semantic checks suppress PY-WL-009."""

    def test_isinstance_before_subscript_silent(self) -> None:
        rule = _run_rule(
            """\
isinstance(data, dict)
if data["amount"] > MAX_AMOUNT:
    raise ValueError("too large")
"""
        )

        assert len(rule.findings) == 0

    def test_hasattr_before_subscript_silent(self) -> None:
        rule = _run_rule(
            """\
hasattr(data, "amount")
if data["amount"] > MAX_AMOUNT:
    raise ValueError("too large")
"""
        )

        assert len(rule.findings) == 0

    def test_in_check_before_subscript_silent(self) -> None:
        rule = _run_rule(
            """\
if "amount" in data:
    if data["amount"] > MAX_AMOUNT:
        raise ValueError("too large")
"""
        )

        assert len(rule.findings) == 0

    def test_validate_schema_call_before_silent(self) -> None:
        rule = _run_rule(
            """\
validate_schema(data)
if data["amount"] > MAX_AMOUNT:
    raise ValueError("too large")
"""
        )

        assert len(rule.findings) == 0

    def test_check_shape_call_before_silent(self) -> None:
        rule = _run_rule(
            """\
check_shape(data)
if data["amount"] > 100:
    flag()
"""
        )

        assert len(rule.findings) == 0


# -- Negative: no semantic checks -----------------------------------------


class TestNoSemanticChecks:
    """No semantic checks produce no findings."""

    def test_plain_function_silent(self) -> None:
        rule = _run_rule("x = 1\n")

        assert len(rule.findings) == 0

    def test_subscript_outside_conditional_silent(self) -> None:
        """Subscript access outside if/assert is not a semantic check."""
        rule = _run_rule(
            """\
value = data["amount"]
process(value)
"""
        )

        assert len(rule.findings) == 0

    def test_if_without_subscript_silent(self) -> None:
        rule = _run_rule(
            """\
if x > 10:
    process(x)
"""
        )

        assert len(rule.findings) == 0


# -- Positive: async function ---------------------------------------------


class TestAsyncFunction:
    """Semantic checks in async functions fire PY-WL-009."""

    def test_async_subscript_check_fires(self) -> None:
        rule = _run_rule_module(
            """\
async def target():
    if data["amount"] > MAX_AMOUNT:
        raise ValueError("too large")
"""
        )

        assert len(rule.findings) == 1


# -- Edge: nested functions ------------------------------------------------


class TestNestedFunctions:
    """Semantic checks in nested functions produce separate findings."""

    def test_nested_function_fires_separately(self) -> None:
        rule = _run_rule_module(
            """\
def outer():
    if data["x"] > 0:
        pass

    def inner():
        if data["y"] > 0:
            pass
"""
        )

        assert len(rule.findings) == 2


# -- Edge: shape validation in method call ---------------------------------


class TestShapeValidationMethodCall:
    """Shape validation via method call suppresses PY-WL-009."""

    def test_obj_validate_schema_before_silent(self) -> None:
        rule = _run_rule(
            """\
validator.validate_schema(data)
if data["amount"] > 100:
    flag()
"""
        )

        assert len(rule.findings) == 0
