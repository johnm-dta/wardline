"""Tests for tier-aware severity in MVP rules."""
from __future__ import annotations

import ast

from wardline.core.matrix import lookup
from wardline.core.severity import RuleId, Severity
from wardline.core.taints import TaintState
from wardline.manifest.models import BoundaryEntry
from wardline.scanner.context import ScanContext
from wardline.scanner.rules.py_wl_001 import RulePyWl001
from wardline.scanner.rules.py_wl_002 import RulePyWl002
from wardline.scanner.rules.py_wl_003 import RulePyWl003
from wardline.scanner.rules.py_wl_004 import RulePyWl004
from wardline.scanner.rules.py_wl_005 import RulePyWl005


def _make_context(qualname: str, taint: TaintState) -> ScanContext:
    return ScanContext(file_path="test.py", function_level_taint_map={qualname: taint})


def _make_context_with_boundary(
    qualname: str,
    taint: TaintState,
    transition: str,
) -> ScanContext:
    return ScanContext(
        file_path="test.py",
        function_level_taint_map={qualname: taint},
        boundaries=(
            BoundaryEntry(
                function=qualname,
                transition=transition,
                overlay_scope=".",  # cwd is parent of test.py for path_within_scope
            ),
        ),
    )


def _parse_and_visit(rule: object, source: str) -> None:
    tree = ast.parse(source, filename="test.py")
    rule._file_path = "test.py"  # type: ignore[attr-defined]
    rule.findings.clear()  # type: ignore[attr-defined]
    rule.visit(tree)  # type: ignore[attr-defined]


# ── Qualname tracking end-to-end ────────────────────────────────


class TestQualnameLookup:
    """Verify qualname tracking produces the correct taint for class methods."""

    def test_class_method_gets_correct_taint(self) -> None:
        """A method MyService.handle with INTEGRAL context should
        get INTEGRAL taint, not UNKNOWN_RAW."""
        rule = RulePyWl001()
        ctx = _make_context("MyService.handle", TaintState.INTEGRAL)
        rule.set_context(ctx)

        source = (
            'class MyService:\n'
            '    def handle(self):\n'
            '        d = {}\n'
            '        d.get("k", "default")\n'
        )
        _parse_and_visit(rule, source)

        assert len(rule.findings) == 1
        assert rule.findings[0].taint_state == TaintState.INTEGRAL


# ── PY-WL-001 ──────────────────────────────────────────────────


class TestRule001TaintAware:
    """PY-WL-001 severity varies by taint state."""

    def test_audit_trail_produces_error_unconditional(self) -> None:
        rule = RulePyWl001()
        ctx = _make_context("target", TaintState.INTEGRAL)
        rule.set_context(ctx)

        source = 'def target():\n    d = {}\n    d.get("k", "default")\n'
        _parse_and_visit(rule, source)

        assert len(rule.findings) == 1
        f = rule.findings[0]
        cell = lookup(RuleId.PY_WL_001, TaintState.INTEGRAL)
        assert f.taint_state == TaintState.INTEGRAL
        assert f.severity == cell.severity
        assert f.severity == Severity.ERROR

    def test_external_raw_produces_matrix_severity(self) -> None:
        rule = RulePyWl001()
        ctx = _make_context("target", TaintState.EXTERNAL_RAW)
        rule.set_context(ctx)

        source = 'def target():\n    d = {}\n    d.get("k", "default")\n'
        _parse_and_visit(rule, source)

        assert len(rule.findings) == 1
        f = rule.findings[0]
        cell = lookup(RuleId.PY_WL_001, TaintState.EXTERNAL_RAW)
        assert f.taint_state == TaintState.EXTERNAL_RAW
        assert f.severity == cell.severity


# ── PY-WL-002 ──────────────────────────────────────────────────


class TestRule002TaintAware:
    """PY-WL-002 severity varies by taint state."""

    def test_pipeline_produces_matrix_severity(self) -> None:
        rule = RulePyWl002()
        ctx = _make_context("target", TaintState.ASSURED)
        rule.set_context(ctx)

        source = 'def target():\n    getattr(obj, "x", None)\n'
        _parse_and_visit(rule, source)

        assert len(rule.findings) == 1
        f = rule.findings[0]
        cell = lookup(RuleId.PY_WL_002, TaintState.ASSURED)
        assert f.taint_state == TaintState.ASSURED
        assert f.severity == cell.severity


# ── PY-WL-004 ──────────────────────────────────────────────────


class TestRule004TaintAware:
    """PY-WL-004 severity varies by taint state."""

    def test_shape_validated_may_produce_warning(self) -> None:
        rule = RulePyWl004()
        ctx = _make_context("target", TaintState.GUARDED)
        rule.set_context(ctx)

        source = (
            'def target():\n'
            '    try:\n'
            '        pass\n'
            '    except Exception:\n'
            '        pass\n'
        )
        _parse_and_visit(rule, source)

        assert len(rule.findings) >= 1
        f = rule.findings[0]
        cell = lookup(RuleId.PY_WL_004, TaintState.GUARDED)
        assert f.taint_state == TaintState.GUARDED
        assert f.severity == cell.severity
        assert f.severity == Severity.WARNING


# ── PY-WL-005 ──────────────────────────────────────────────────


class TestRule005TaintAware:
    """PY-WL-005 severity varies by taint state."""

    def test_audit_trail_produces_matrix_severity(self) -> None:
        rule = RulePyWl005()
        ctx = _make_context("target", TaintState.INTEGRAL)
        rule.set_context(ctx)

        source = (
            'def target():\n'
            '    try:\n'
            '        pass\n'
            '    except Exception:\n'
            '        pass\n'
        )
        _parse_and_visit(rule, source)

        assert len(rule.findings) == 1
        f = rule.findings[0]
        cell = lookup(RuleId.PY_WL_005, TaintState.INTEGRAL)
        assert f.taint_state == TaintState.INTEGRAL
        assert f.severity == cell.severity


# ── PY-WL-003 ───────────────────────────────────────────────

_SRC_003 = 'def target():\n    d = {}\n    if "key" in d:\n        pass\n'


class TestRule003TaintAware:
    """PY-WL-003 follows the matrix unless a validation boundary suppresses it."""

    def test_fires_at_external_raw(self) -> None:
        rule = RulePyWl003()
        rule.set_context(_make_context("target", TaintState.EXTERNAL_RAW))
        _parse_and_visit(rule, _SRC_003)
        assert len(rule.findings) >= 1
        assert rule.findings[0].taint_state == TaintState.EXTERNAL_RAW

    def test_fires_at_unknown_raw(self) -> None:
        rule = RulePyWl003()
        rule.set_context(_make_context("target", TaintState.UNKNOWN_RAW))
        _parse_and_visit(rule, _SRC_003)
        assert len(rule.findings) >= 1

    def test_fires_at_mixed_raw(self) -> None:
        rule = RulePyWl003()
        rule.set_context(_make_context("target", TaintState.MIXED_RAW))
        _parse_and_visit(rule, _SRC_003)
        assert len(rule.findings) >= 1

    def test_audit_trail_uses_matrix(self) -> None:
        rule = RulePyWl003()
        rule.set_context(_make_context("target", TaintState.INTEGRAL))
        _parse_and_visit(rule, _SRC_003)
        assert len(rule.findings) >= 1
        f = rule.findings[0]
        cell = lookup(RuleId.PY_WL_003, TaintState.INTEGRAL)
        assert f.taint_state == TaintState.INTEGRAL
        assert f.severity == cell.severity

    def test_pipeline_uses_matrix(self) -> None:
        rule = RulePyWl003()
        rule.set_context(_make_context("target", TaintState.ASSURED))
        _parse_and_visit(rule, _SRC_003)
        assert len(rule.findings) >= 1
        f = rule.findings[0]
        cell = lookup(RuleId.PY_WL_003, TaintState.ASSURED)
        assert f.taint_state == TaintState.ASSURED
        assert f.severity == cell.severity

    def test_shape_validated_uses_matrix_without_boundary(self) -> None:
        rule = RulePyWl003()
        rule.set_context(_make_context("target", TaintState.GUARDED))
        _parse_and_visit(rule, _SRC_003)
        assert len(rule.findings) >= 1
        f = rule.findings[0]
        cell = lookup(RuleId.PY_WL_003, TaintState.GUARDED)
        assert f.taint_state == TaintState.GUARDED
        assert f.severity == cell.severity

    def test_unknown_sem_validated_uses_matrix(self) -> None:
        rule = RulePyWl003()
        rule.set_context(_make_context("target", TaintState.UNKNOWN_ASSURED))
        _parse_and_visit(rule, _SRC_003)
        assert len(rule.findings) >= 1
        f = rule.findings[0]
        cell = lookup(RuleId.PY_WL_003, TaintState.UNKNOWN_ASSURED)
        assert f.taint_state == TaintState.UNKNOWN_ASSURED
        assert f.severity == cell.severity

    def test_shape_validation_boundary_suppresses(self) -> None:
        rule = RulePyWl003()
        rule.set_context(
            _make_context_with_boundary(
                "target",
                TaintState.EXTERNAL_RAW,
                "shape_validation",
            )
        )
        _parse_and_visit(rule, _SRC_003)
        assert len(rule.findings) == 0

    def test_validates_external_boundary_suppresses(self) -> None:
        rule = RulePyWl003()
        rule.set_context(
            _make_context_with_boundary(
                "target",
                TaintState.EXTERNAL_RAW,
                "validates_external",
            )
        )
        _parse_and_visit(rule, _SRC_003)
        assert len(rule.findings) == 0
