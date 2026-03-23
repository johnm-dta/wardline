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
            TaintState.AUDIT_TRAIL,
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
            TaintState.PIPELINE,
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
