"""Tests for PY-WL-004: Broad Exception Handlers."""

from __future__ import annotations

from wardline.core.severity import RuleId, Severity
from wardline.scanner.rules.py_wl_004 import RulePyWl004

from .conftest import parse_function_source, parse_module_source


def _run_rule(source: str) -> RulePyWl004:
    """Parse source inside a function and run PY-WL-004."""
    tree = parse_function_source(source)
    rule = RulePyWl004(file_path="test.py")
    rule.visit(tree)
    return rule


def _run_rule_module(source: str) -> RulePyWl004:
    """Parse raw module source and run PY-WL-004."""
    tree = parse_module_source(source)
    rule = RulePyWl004(file_path="test.py")
    rule.visit(tree)
    return rule


# -- Positive: bare except fires -----------------------------------------


class TestBareExcept:
    """Bare ``except:`` fires PY-WL-004."""

    def test_bare_except_fires(self) -> None:
        rule = _run_rule(
            """\
try:
    pass
except:
    pass
"""
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_004
        assert rule.findings[0].severity == Severity.ERROR
        assert "bare 'except:'" in rule.findings[0].message


# -- Positive: except Exception fires ------------------------------------


class TestExceptException:
    """``except Exception:`` fires PY-WL-004."""

    def test_except_exception_fires(self) -> None:
        rule = _run_rule(
            """\
try:
    pass
except Exception:
    pass
"""
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_004
        assert "'except Exception'" in rule.findings[0].message

    def test_except_exception_as_e_fires(self) -> None:
        rule = _run_rule(
            """\
try:
    pass
except Exception as e:
    pass
"""
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_004


# -- Positive: except BaseException fires --------------------------------


class TestExceptBaseException:
    """``except BaseException:`` fires PY-WL-004."""

    def test_except_base_exception_fires(self) -> None:
        rule = _run_rule(
            """\
try:
    pass
except BaseException:
    pass
"""
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_004
        assert "'except BaseException'" in rule.findings[0].message


# -- Positive: multiple broad handlers -----------------------------------


class TestMultipleBroadHandlers:
    """Multiple broad handlers in the same function each produce a finding."""

    def test_multiple_broad_handlers(self) -> None:
        rule = _run_rule(
            """\
try:
    pass
except Exception:
    pass

try:
    pass
except:
    pass
"""
        )

        assert len(rule.findings) == 2


# -- Positive: async function -------------------------------------------


class TestAsyncFunction:
    """Broad handlers in async functions fire PY-WL-004."""

    def test_async_bare_except_fires(self) -> None:
        rule = _run_rule_module(
            """\
async def target():
    try:
        pass
    except:
        pass
"""
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_004


# -- Positive: TryStar (except*) with broad type -------------------------


class TestTryStar:
    """``except*`` with broad exception type fires PY-WL-004."""

    def test_except_star_exception_fires(self) -> None:
        rule = _run_rule_module(
            """\
def target():
    try:
        pass
    except* Exception:
        pass
"""
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_004


# -- Negative: specific exceptions are silent ----------------------------


class TestSpecificExceptions:
    """Specific exception types do NOT fire PY-WL-004."""

    def test_except_value_error_silent(self) -> None:
        rule = _run_rule(
            """\
try:
    pass
except ValueError:
    pass
"""
        )

        assert len(rule.findings) == 0

    def test_except_tuple_specific_silent(self) -> None:
        rule = _run_rule(
            """\
try:
    pass
except (TypeError, ValueError):
    pass
"""
        )

        assert len(rule.findings) == 0

    def test_except_key_error_as_e_silent(self) -> None:
        rule = _run_rule(
            """\
try:
    pass
except KeyError as e:
    pass
"""
        )

        assert len(rule.findings) == 0

    def test_no_try_except_silent(self) -> None:
        rule = _run_rule("x = 1\n")

        assert len(rule.findings) == 0
