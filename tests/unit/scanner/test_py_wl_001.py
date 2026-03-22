"""Tests for PY-WL-001: Dict key access with fallback default."""

from __future__ import annotations

from wardline.core.severity import RuleId, Severity
from wardline.scanner.rules.py_wl_001 import RulePyWl001

from .conftest import parse_function_source, parse_module_source


def _run_rule(source: str) -> RulePyWl001:
    """Parse source inside a function and run PY-WL-001."""
    tree = parse_function_source(source)
    rule = RulePyWl001(file_path="test.py")
    rule.visit(tree)
    return rule


def _run_rule_module(source: str) -> RulePyWl001:
    """Parse raw module source and run PY-WL-001."""
    tree = parse_module_source(source)
    rule = RulePyWl001(file_path="test.py")
    rule.visit(tree)
    return rule


# ── Positive: .get() with default ────────────────────────────────


class TestGetWithDefault:
    """``d.get(key, default)`` fires PY-WL-001."""

    def test_get_with_default_fires(self) -> None:
        rule = _run_rule('d.get("key", "fallback")\n')

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001
        assert rule.findings[0].severity == Severity.ERROR

    def test_get_with_none_default_fires(self) -> None:
        rule = _run_rule('d.get("key", None)\n')

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001

    def test_get_with_variable_default_fires(self) -> None:
        rule = _run_rule('d.get("key", fallback_value)\n')

        assert len(rule.findings) == 1


# ── Negative: .get() without default ─────────────────────────────


class TestGetWithoutDefault:
    """``d.get(key)`` (no default) does NOT fire PY-WL-001."""

    def test_get_without_default_silent(self) -> None:
        rule = _run_rule('d.get("key")\n')

        assert len(rule.findings) == 0

    def test_get_no_args_silent(self) -> None:
        """Edge case: .get() with no args (will fail at runtime, not our problem)."""
        rule = _run_rule("d.get()\n")

        assert len(rule.findings) == 0


# ── Positive: .setdefault() ──────────────────────────────────────


class TestSetdefault:
    """``d.setdefault(key, default)`` fires PY-WL-001."""

    def test_setdefault_with_default_fires(self) -> None:
        rule = _run_rule('d.setdefault("key", [])\n')

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001

    def test_setdefault_one_arg_silent(self) -> None:
        """setdefault with only key arg doesn't fire."""
        rule = _run_rule('d.setdefault("key")\n')

        assert len(rule.findings) == 0


# ── Positive: defaultdict ────────────────────────────────────────


class TestDefaultdict:
    """``defaultdict(factory)`` fires PY-WL-001."""

    def test_defaultdict_with_factory_fires(self) -> None:
        rule = _run_rule("defaultdict(list)\n")

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001

    def test_defaultdict_with_lambda_fires(self) -> None:
        rule = _run_rule("defaultdict(lambda: 0)\n")

        assert len(rule.findings) == 1

    def test_defaultdict_no_args_fires(self) -> None:
        """Even no-arg defaultdict registers a None factory."""
        rule = _run_rule("defaultdict()\n")

        assert len(rule.findings) == 1


# ── schema_default() suppression ─────────────────────────────────


class TestSchemaDefault:
    """``schema_default()`` suppresses to WARNING, not silence."""

    def test_get_with_schema_default_emits_warning(self) -> None:
        rule = _run_rule('d.get("key", schema_default("fallback"))\n')

        assert len(rule.findings) == 1
        f = rule.findings[0]
        assert f.rule_id == RuleId.PY_WL_001_UNVERIFIED_DEFAULT
        assert f.severity == Severity.WARNING
        assert "un-governed" in f.message

    def test_setdefault_with_schema_default_emits_warning(self) -> None:
        rule = _run_rule(
            'd.setdefault("key", schema_default([]))\n'
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001_UNVERIFIED_DEFAULT
        assert rule.findings[0].severity == Severity.WARNING

    def test_schema_default_does_not_produce_error(self) -> None:
        """schema_default should NOT produce an ERROR-level PY-WL-001."""
        rule = _run_rule('d.get("key", schema_default(42))\n')

        error_findings = [
            f for f in rule.findings if f.rule_id == RuleId.PY_WL_001
        ]
        assert len(error_findings) == 0


# ── Lambda .get() corpus specimen ────────────────────────────────


class TestLambdaGet:
    """Lambda containing .get() — corpus specimen for known behaviour."""

    def test_lambda_get_in_function_body(self) -> None:
        """Lambda .get() inside a function IS detected (ast.walk covers it)."""
        rule = _run_rule('fn = lambda d: d.get("key", "default")\n')

        # ast.walk inside visit_function covers lambda bodies
        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001


# ── Multiple patterns in one function ────────────────────────────


class TestMultiplePatterns:
    """Multiple violations in one function each produce a finding."""

    def test_multiple_gets_produce_multiple_findings(self) -> None:
        rule = _run_rule("""\
            a = d.get("x", 1)
            b = d.get("y", 2)
        """)

        assert len(rule.findings) == 2

    def test_mixed_patterns(self) -> None:
        rule = _run_rule("""\
            a = d.get("x", 1)
            b = d.setdefault("y", [])
            c = defaultdict(int)
        """)

        assert len(rule.findings) == 3


# ── No false positives ──────────────────────────────────────────


class TestNoFalsePositives:
    """Patterns that should NOT fire PY-WL-001."""

    def test_regular_method_call_silent(self) -> None:
        rule = _run_rule('d.items()\n')

        assert len(rule.findings) == 0

    def test_dict_subscript_silent(self) -> None:
        rule = _run_rule('x = d["key"]\n')

        assert len(rule.findings) == 0

    def test_regular_function_call_silent(self) -> None:
        rule = _run_rule("print(d)\n")

        assert len(rule.findings) == 0

    def test_get_on_non_dict_silent(self) -> None:
        """We can't distinguish dict.get from other .get — this fires.
        This is a known over-approximation at Level 1."""
        # Note: obj.get("x", default) fires because we can't do
        # type inference at Level 1. This is acceptable — Level 2
        # adds type-aware suppression.
        rule = _run_rule('obj.get("key", "default")\n')

        assert len(rule.findings) == 1  # Expected: fires (over-approx)
