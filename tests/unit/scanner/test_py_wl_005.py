"""Tests for PY-WL-005: Silent exception handling."""

from __future__ import annotations

import sys

import pytest

from wardline.core.severity import RuleId, Severity
from wardline.scanner.rules.py_wl_005 import RulePyWl005

from .conftest import parse_function_source, parse_module_source


def _run_rule(source: str) -> RulePyWl005:
    """Parse source inside a function and run PY-WL-005."""
    tree = parse_function_source(source)
    rule = RulePyWl005(file_path="test.py")
    rule.visit(tree)
    return rule


def _run_rule_module(source: str) -> RulePyWl005:
    """Parse raw module source and run PY-WL-005."""
    tree = parse_module_source(source)
    rule = RulePyWl005(file_path="test.py")
    rule.visit(tree)
    return rule


# ── Positive: pass body ─────────────────────────────────────────


class TestPassBody:
    """``except: pass`` fires PY-WL-005."""

    def test_bare_except_pass(self) -> None:
        rule = _run_rule("""\
            try:
                x = 1
            except:
                pass
        """)

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_005
        assert rule.findings[0].severity == Severity.ERROR
        assert "'pass'" in rule.findings[0].message

    def test_typed_except_pass(self) -> None:
        rule = _run_rule("""\
            try:
                x = 1
            except Exception:
                pass
        """)

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_005

    def test_specific_exception_pass(self) -> None:
        rule = _run_rule("""\
            try:
                x = 1
            except ValueError:
                pass
        """)

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_005


# ── Positive: Ellipsis body ──────────────────────────────────────


class TestEllipsisBody:
    """``except: ...`` fires PY-WL-005."""

    def test_bare_except_ellipsis(self) -> None:
        rule = _run_rule("""\
            try:
                x = 1
            except:
                ...
        """)

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_005
        assert "'...'" in rule.findings[0].message


# ── Positive: continue body ──────────────────────────────────────


class TestContinueBody:
    """``except: continue`` fires PY-WL-005."""

    def test_except_continue(self) -> None:
        rule = _run_rule("""\
            for x in range(10):
                try:
                    y = 1
                except:
                    continue
        """)

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_005
        assert "'continue'" in rule.findings[0].message


# ── Positive: break body ─────────────────────────────────────────


class TestBreakBody:
    """``except: break`` fires PY-WL-005."""

    def test_except_break(self) -> None:
        rule = _run_rule("""\
            for x in range(10):
                try:
                    y = 1
                except:
                    break
        """)

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_005
        assert "'break'" in rule.findings[0].message


# ── Positive: multiple handlers ──────────────────────────────────


class TestMultipleHandlers:
    """Multiple silent handlers in one function each produce a finding."""

    def test_two_silent_handlers(self) -> None:
        rule = _run_rule("""\
            try:
                x = 1
            except ValueError:
                pass
            try:
                y = 2
            except TypeError:
                ...
        """)

        assert len(rule.findings) == 2


# ── Positive: async function ─────────────────────────────────────


class TestAsyncFunction:
    """Silent handler inside async function fires."""

    def test_async_except_pass(self) -> None:
        rule = _run_rule_module("""\
            async def handler():
                try:
                    await something()
                except:
                    pass
        """)

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_005


# ── Positive: TryStar (except*) ──────────────────────────────────


class TestTryStar:
    """``except* Exception: pass`` fires PY-WL-005 (Python 3.11+)."""

    @pytest.mark.skipif(
        sys.version_info < (3, 11),
        reason="except* requires Python 3.11+",
    )
    def test_except_star_pass(self) -> None:
        rule = _run_rule("""\
            try:
                x = 1
            except* Exception:
                pass
        """)

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_005


# ── Negative: meaningful handler body ────────────────────────────


class TestNegativeMeaningfulBody:
    """Handlers with meaningful bodies do NOT fire PY-WL-005."""

    def test_logging_call_silent(self) -> None:
        rule = _run_rule("""\
            try:
                x = 1
            except:
                logging.warning("error")
        """)

        assert len(rule.findings) == 0

    def test_reraise_silent(self) -> None:
        rule = _run_rule("""\
            try:
                x = 1
            except:
                raise
        """)

        assert len(rule.findings) == 0

    def test_assignment_silent(self) -> None:
        rule = _run_rule("""\
            try:
                x = 1
            except:
                x = 1
        """)

        assert len(rule.findings) == 0

    def test_print_call_silent(self) -> None:
        rule = _run_rule("""\
            try:
                x = 1
            except:
                print("error")
        """)

        assert len(rule.findings) == 0

    def test_pass_with_extra_statement_silent(self) -> None:
        """Body has 2 statements — not silent even though pass is present."""
        rule = _run_rule("""\
            try:
                x = 1
            except:
                pass
                logging.info("x")
        """)

        assert len(rule.findings) == 0


# ── Negative: no try/except ──────────────────────────────────────


class TestNoTryExcept:
    """Code without try/except does NOT fire PY-WL-005."""

    def test_no_try_except(self) -> None:
        rule = _run_rule("x = 1\n")

        assert len(rule.findings) == 0
