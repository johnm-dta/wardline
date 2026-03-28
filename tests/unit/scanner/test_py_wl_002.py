"""Tests for PY-WL-002: Attribute access with fallback default."""

from __future__ import annotations

from wardline.core.severity import RuleId, Severity
from wardline.scanner.rules.py_wl_002 import RulePyWl002

from .conftest import parse_function_source, parse_module_source


def _run_rule(source: str) -> RulePyWl002:
    """Parse source inside a function and run PY-WL-002."""
    tree = parse_function_source(source)
    rule = RulePyWl002(file_path="test.py")
    rule.visit(tree)
    return rule


def _run_rule_module(source: str) -> RulePyWl002:
    """Parse raw module source and run PY-WL-002."""
    tree = parse_module_source(source)
    rule = RulePyWl002(file_path="test.py")
    rule.visit(tree)
    return rule


# ── Positive: 3-arg getattr fires ───────────────────────────────


class TestGetattrWithDefault:
    """``getattr(obj, name, default)`` fires PY-WL-002."""

    def test_getattr_3arg_fires(self) -> None:
        rule = _run_rule('getattr(obj, "name", default)\n')

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_002
        assert rule.findings[0].severity == Severity.WARNING

    def test_getattr_3arg_none_default_fires(self) -> None:
        rule = _run_rule('getattr(obj, "name", None)\n')

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_002

    def test_getattr_3arg_variable_args_fires(self) -> None:
        rule = _run_rule("getattr(obj, attr_var, some_default)\n")

        assert len(rule.findings) == 1


class TestAttributeOrDefault:
    """``obj.attr or default`` fires PY-WL-002."""

    def test_attribute_or_default_fires(self) -> None:
        rule = _run_rule('value = obj.name or "fallback"\n')

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_002

    def test_self_attribute_or_default_fires(self) -> None:
        rule = _run_rule("value = self.cached_value or default_value\n")

        assert len(rule.findings) == 1


# ── Multiple getattr in same function ────────────────────────────


class TestMultipleGetattr:
    """Multiple 3-arg getattr calls each produce a finding."""

    def test_multiple_getattr_produce_multiple_findings(self) -> None:
        rule = _run_rule("""\
            a = getattr(obj, "x", 1)
            b = getattr(obj, "y", 2)
        """)

        assert len(rule.findings) == 2


# ── Async function ───────────────────────────────────────────────


class TestAsyncFunction:
    """3-arg getattr in async function fires PY-WL-002."""

    def test_async_function_fires(self) -> None:
        rule = _run_rule_module("""\
            async def do_stuff():
                val = getattr(obj, "name", None)
        """)

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_002


# ── Negative: should NOT fire ────────────────────────────────────


class TestNegative:
    """Patterns that should NOT fire PY-WL-002."""

    def test_getattr_2arg_silent(self) -> None:
        """2-arg getattr does NOT fire."""
        rule = _run_rule('getattr(obj, "name")\n')

        assert len(rule.findings) == 0

    def test_hasattr_silent(self) -> None:
        """hasattr is NOT detected by this rule (that's PY-WL-003)."""
        rule = _run_rule('hasattr(obj, "name")\n')

        assert len(rule.findings) == 0

    def test_setattr_silent(self) -> None:
        """setattr is not getattr."""
        rule = _run_rule('setattr(obj, "name", value)\n')

        assert len(rule.findings) == 0

    def test_no_getattr_silent(self) -> None:
        """No getattr at all — empty findings."""
        rule = _run_rule("x = 1 + 2\n")

        assert len(rule.findings) == 0

    def test_attribute_and_default_silent(self) -> None:
        """Logical and is not a fallback-default pattern."""
        rule = _run_rule('value = obj.name and "fallback"\n')

        assert len(rule.findings) == 0

    def test_method_call_or_default_silent(self) -> None:
        """Method result fallback is not attribute access fallback."""
        rule = _run_rule('value = obj.name() or "fallback"\n')

        assert len(rule.findings) == 0
