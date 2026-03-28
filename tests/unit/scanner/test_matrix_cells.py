"""Parametrized severity matrix cell tests for all 9 binding rules.

Each test injects a specific taint state via ScanContext and verifies
the resulting (severity, exceptionability) pair matches the spec S7.3
severity matrix.  This is the conformance safety net -- a regression in
matrix.py data will be caught by these tests.

72 test cases total: 9 rules x 8 taint states.
"""

from __future__ import annotations

import pytest

from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.core.taints import TaintState
from wardline.manifest.models import BoundaryEntry
from wardline.scanner.context import ScanContext
from wardline.scanner.rules.py_wl_001 import RulePyWl001
from wardline.scanner.rules.py_wl_002 import RulePyWl002
from wardline.scanner.rules.py_wl_003 import RulePyWl003
from wardline.scanner.rules.py_wl_004 import RulePyWl004
from wardline.scanner.rules.py_wl_005 import RulePyWl005
from wardline.scanner.rules.py_wl_006 import RulePyWl006
from wardline.scanner.rules.py_wl_007 import RulePyWl007
from wardline.scanner.rules.py_wl_008 import RulePyWl008
from wardline.scanner.rules.py_wl_009 import RulePyWl009

from .conftest import parse_function_source

# -- Aliases for readability --
E = Severity.ERROR
W = Severity.WARNING
Su = Severity.SUPPRESS
U = Exceptionability.UNCONDITIONAL
St = Exceptionability.STANDARD
R = Exceptionability.RELAXED
T = Exceptionability.TRANSPARENT

# Taint states in canonical matrix column order
TAINT_STATES = [
    TaintState.AUDIT_TRAIL,
    TaintState.PIPELINE,
    TaintState.SHAPE_VALIDATED,
    TaintState.EXTERNAL_RAW,
    TaintState.UNKNOWN_RAW,
    TaintState.UNKNOWN_SHAPE_VALIDATED,
    TaintState.UNKNOWN_SEM_VALIDATED,
    TaintState.MIXED_RAW,
]

# -- Spec S7.3 severity matrix (authoritative reference) --
MATRIX: dict[RuleId, list[tuple[Severity, Exceptionability]]] = {
    RuleId.PY_WL_001: [(E, U), (E, St), (W, R), (Su, T), (Su, T), (W, R), (E, St), (Su, T)],
    RuleId.PY_WL_002: [(E, U), (E, St), (W, R), (W, R), (W, R), (W, R), (E, St), (W, St)],
    RuleId.PY_WL_003: [(E, U), (E, U), (E, St), (Su, T), (Su, T), (E, St), (E, St), (Su, T)],
    RuleId.PY_WL_004: [(E, U), (E, St), (W, St), (W, R), (E, St), (W, St), (W, St), (E, St)],
    RuleId.PY_WL_005: [(E, U), (E, St), (E, St), (E, St), (E, St), (E, St), (E, St), (E, St)],
    RuleId.PY_WL_006: [(E, U), (E, U), (E, St), (E, St), (E, St), (E, St), (E, St), (E, St)],
    RuleId.PY_WL_007: [(E, St), (W, R), (W, R), (Su, T), (Su, T), (W, R), (W, R), (W, St)],
    RuleId.PY_WL_008: [(E, U), (E, U), (E, U), (E, U), (E, U), (E, U), (E, U), (E, U)],
    RuleId.PY_WL_009: [(E, U), (E, U), (E, U), (E, U), (E, U), (E, U), (E, U), (E, U)],
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FILE_PATH = "/project/src/api/handler.py"
_OVERLAY_SCOPE = "/project/src/api"


def _make_context(
    taint: TaintState,
    *,
    boundaries: tuple[BoundaryEntry, ...] = (),
) -> ScanContext:
    return ScanContext(
        file_path=_FILE_PATH,
        function_level_taint_map={"target": taint},
        boundaries=boundaries,
    )


def _boundary(
    *,
    qualname: str = "target",
    transition: str = "shape_validation",
    overlay_scope: str = _OVERLAY_SCOPE,
) -> BoundaryEntry:
    return BoundaryEntry(
        function=qualname,
        transition=transition,
        overlay_scope=overlay_scope,
    )


# ---------------------------------------------------------------------------
# Generic runner for rules 001-005 and 007
# ---------------------------------------------------------------------------

# Trigger snippets -- minimal code that reliably fires each rule.
_TRIGGER_SNIPPETS: dict[RuleId, str] = {
    RuleId.PY_WL_001: 'd.get("key", "default")\n',
    RuleId.PY_WL_002: 'getattr(obj, "attr", "default")\n',
    RuleId.PY_WL_003: '"key" in d\n',
    RuleId.PY_WL_004: "try:\n    x = 1\nexcept Exception:\n    log(x)\n",
    RuleId.PY_WL_005: "try:\n    x = 1\nexcept Exception:\n    pass\n",
    RuleId.PY_WL_007: "isinstance(data, dict)\n",
}

# Rule class for each rule ID.
_RULE_CLASSES: dict[RuleId, type] = {
    RuleId.PY_WL_001: RulePyWl001,
    RuleId.PY_WL_002: RulePyWl002,
    RuleId.PY_WL_003: RulePyWl003,
    RuleId.PY_WL_004: RulePyWl004,
    RuleId.PY_WL_005: RulePyWl005,
    RuleId.PY_WL_007: RulePyWl007,
}


def _run_generic(rule_id: RuleId, taint: TaintState) -> list:
    """Run a generic rule (001-005, 007) with the given taint and return findings."""
    snippet = _TRIGGER_SNIPPETS[rule_id]
    tree = parse_function_source(snippet)
    rule_cls = _RULE_CLASSES[rule_id]
    rule = rule_cls(file_path=_FILE_PATH)
    ctx = _make_context(taint)
    rule.set_context(ctx)
    rule.visit(tree)
    return [f for f in rule.findings if f.rule_id == rule_id]


# ---------------------------------------------------------------------------
# Build parametrize matrix for generic rules
# ---------------------------------------------------------------------------

_GENERIC_RULE_IDS = [
    RuleId.PY_WL_001,
    RuleId.PY_WL_002,
    RuleId.PY_WL_003,
    RuleId.PY_WL_004,
    RuleId.PY_WL_005,
    RuleId.PY_WL_007,
]

_generic_params = []
for _rid in _GENERIC_RULE_IDS:
    for _idx, _ts in enumerate(TAINT_STATES):
        _expected_sev, _expected_exc = MATRIX[_rid][_idx]
        _generic_params.append(
            pytest.param(
                _rid, _ts, _expected_sev, _expected_exc,
                id=f"{_rid.value}-{_ts.value}",
            )
        )


class TestGenericMatrixCells:
    """Matrix cell tests for PY-WL-001 through PY-WL-005 and PY-WL-007."""

    @pytest.mark.parametrize(
        ("rule_id", "taint", "expected_severity", "expected_exceptionability"),
        _generic_params,
    )
    def test_matrix_cell(
        self,
        rule_id: RuleId,
        taint: TaintState,
        expected_severity: Severity,
        expected_exceptionability: Exceptionability,
    ) -> None:
        findings = _run_generic(rule_id, taint)

        if expected_severity == Su:
            # SUPPRESS cells: rule MUST still fire with SUPPRESS severity.
            # A rule that silently stops emitting findings would be a regression.
            assert len(findings) >= 1, (
                f"Expected SUPPRESS finding for {rule_id.value} at taint {taint.value}, "
                f"got 0 findings"
            )
            assert findings[0].severity == expected_severity
            assert findings[0].exceptionability == expected_exceptionability
        else:
            assert len(findings) >= 1, (
                f"Expected finding for {rule_id.value} at taint {taint.value}"
            )
            assert findings[0].severity == expected_severity
            assert findings[0].exceptionability == expected_exceptionability


# ---------------------------------------------------------------------------
# PY-WL-006: Audit-critical writes in broad exception handlers
# ---------------------------------------------------------------------------

def _run_006(taint: TaintState) -> list:
    """Run PY-WL-006 with an audit call inside a broad handler."""
    source = """\
try:
    process(data)
except Exception:
    audit.emit("event_failed", data)
"""
    tree = parse_function_source(source)
    rule = RulePyWl006(file_path=_FILE_PATH)
    ctx = _make_context(taint)
    rule.set_context(ctx)
    rule.visit(tree)
    return [f for f in rule.findings if f.rule_id == RuleId.PY_WL_006]


_006_params = []
for _idx, _ts in enumerate(TAINT_STATES):
    _expected_sev, _expected_exc = MATRIX[RuleId.PY_WL_006][_idx]
    _006_params.append(
        pytest.param(
            _ts, _expected_sev, _expected_exc,
            id=f"PY-WL-006-{_ts.value}",
        )
    )


class TestPyWl006MatrixCells:
    """Matrix cell tests for PY-WL-006."""

    @pytest.mark.parametrize(
        ("taint", "expected_severity", "expected_exceptionability"),
        _006_params,
    )
    def test_matrix_cell(
        self,
        taint: TaintState,
        expected_severity: Severity,
        expected_exceptionability: Exceptionability,
    ) -> None:
        findings = _run_006(taint)
        assert len(findings) >= 1, (
            f"Expected finding for PY-WL-006 at taint {taint.value}"
        )
        assert findings[0].severity == expected_severity
        assert findings[0].exceptionability == expected_exceptionability


# ---------------------------------------------------------------------------
# PY-WL-008: Declared boundary with no rejection path
# ---------------------------------------------------------------------------

def _run_008(taint: TaintState) -> list:
    """Run PY-WL-008 with a boundary declaration and no rejection path."""
    source = """\
result = validate(data)
return data
"""
    tree = parse_function_source(source)
    rule = RulePyWl008(file_path=_FILE_PATH)
    ctx = _make_context(
        taint,
        boundaries=(_boundary(),),
    )
    rule.set_context(ctx)
    rule.visit(tree)
    return [f for f in rule.findings if f.rule_id == RuleId.PY_WL_008]


_008_params = []
for _idx, _ts in enumerate(TAINT_STATES):
    _expected_sev, _expected_exc = MATRIX[RuleId.PY_WL_008][_idx]
    _008_params.append(
        pytest.param(
            _ts, _expected_sev, _expected_exc,
            id=f"PY-WL-008-{_ts.value}",
        )
    )


class TestPyWl008MatrixCells:
    """Matrix cell tests for PY-WL-008."""

    @pytest.mark.parametrize(
        ("taint", "expected_severity", "expected_exceptionability"),
        _008_params,
    )
    def test_matrix_cell(
        self,
        taint: TaintState,
        expected_severity: Severity,
        expected_exceptionability: Exceptionability,
    ) -> None:
        findings = _run_008(taint)
        assert len(findings) >= 1, (
            f"Expected finding for PY-WL-008 at taint {taint.value}"
        )
        assert findings[0].severity == expected_severity
        assert findings[0].exceptionability == expected_exceptionability


# ---------------------------------------------------------------------------
# PY-WL-009: Semantic boundary without prior shape validation
# ---------------------------------------------------------------------------

def _run_009(taint: TaintState) -> list:
    """Run PY-WL-009 with a semantic boundary and no shape evidence."""
    source = """\
if data["amount"] > 100:
    reject()
"""
    tree = parse_function_source(source)
    rule = RulePyWl009(file_path=_FILE_PATH)
    ctx = _make_context(
        taint,
        boundaries=(
            _boundary(transition="semantic_validation"),
        ),
    )
    rule.set_context(ctx)
    rule.visit(tree)
    return [f for f in rule.findings if f.rule_id == RuleId.PY_WL_009]


_009_params = []
for _idx, _ts in enumerate(TAINT_STATES):
    _expected_sev, _expected_exc = MATRIX[RuleId.PY_WL_009][_idx]
    _009_params.append(
        pytest.param(
            _ts, _expected_sev, _expected_exc,
            id=f"PY-WL-009-{_ts.value}",
        )
    )


class TestPyWl009MatrixCells:
    """Matrix cell tests for PY-WL-009."""

    @pytest.mark.parametrize(
        ("taint", "expected_severity", "expected_exceptionability"),
        _009_params,
    )
    def test_matrix_cell(
        self,
        taint: TaintState,
        expected_severity: Severity,
        expected_exceptionability: Exceptionability,
    ) -> None:
        findings = _run_009(taint)
        assert len(findings) >= 1, (
            f"Expected finding for PY-WL-009 at taint {taint.value}"
        )
        assert findings[0].severity == expected_severity
        assert findings[0].exceptionability == expected_exceptionability
