"""Tests for severity matrix — independently encoded fixture.

IMPORTANT: This test file MUST NOT import from wardline.core.matrix.
The expected values are encoded independently to catch errors in the
matrix definition itself. The CI check verifies this constraint.
"""

import pytest

# Deliberately import only the enums, NOT the matrix module
from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.core.taints import TaintState

E = Severity.ERROR
W = Severity.WARNING
Su = Severity.SUPPRESS

U = Exceptionability.UNCONDITIONAL
St = Exceptionability.STANDARD
R = Exceptionability.RELAXED
T = Exceptionability.TRANSPARENT

# Independent fixture: (rule, taint, expected_severity, expected_exceptionability)
# Encoded directly from spec §7.3 table, NOT copied from matrix.py
# fmt: off
EXPECTED: list[tuple[RuleId, TaintState, Severity, Exceptionability]] = [
    # PY-WL-001 (dict key access with fallback default) — inherits WL-001
    (RuleId.PY_WL_001, TaintState.AUDIT_TRAIL, E, U),
    (RuleId.PY_WL_001, TaintState.PIPELINE, E, St),
    (RuleId.PY_WL_001, TaintState.SHAPE_VALIDATED, E, St),
    (RuleId.PY_WL_001, TaintState.EXTERNAL_RAW, E, St),
    (RuleId.PY_WL_001, TaintState.UNKNOWN_RAW, E, St),
    (RuleId.PY_WL_001, TaintState.UNKNOWN_SHAPE_VALIDATED, E, St),
    (RuleId.PY_WL_001, TaintState.UNKNOWN_SEM_VALIDATED, E, St),
    (RuleId.PY_WL_001, TaintState.MIXED_RAW, E, St),

    # PY-WL-002 (attribute access with fallback default) — inherits WL-001
    (RuleId.PY_WL_002, TaintState.AUDIT_TRAIL, E, U),
    (RuleId.PY_WL_002, TaintState.PIPELINE, E, St),
    (RuleId.PY_WL_002, TaintState.SHAPE_VALIDATED, E, St),
    (RuleId.PY_WL_002, TaintState.EXTERNAL_RAW, E, St),
    (RuleId.PY_WL_002, TaintState.UNKNOWN_RAW, E, St),
    (RuleId.PY_WL_002, TaintState.UNKNOWN_SHAPE_VALIDATED, E, St),
    (RuleId.PY_WL_002, TaintState.UNKNOWN_SEM_VALIDATED, E, St),
    (RuleId.PY_WL_002, TaintState.MIXED_RAW, E, St),

    # PY-WL-003 = WL-002 (existence-checking as structural gate)
    (RuleId.PY_WL_003, TaintState.AUDIT_TRAIL, E, U),
    (RuleId.PY_WL_003, TaintState.PIPELINE, E, U),
    (RuleId.PY_WL_003, TaintState.SHAPE_VALIDATED, E, U),
    (RuleId.PY_WL_003, TaintState.EXTERNAL_RAW, E, St),
    (RuleId.PY_WL_003, TaintState.UNKNOWN_RAW, E, St),
    (RuleId.PY_WL_003, TaintState.UNKNOWN_SHAPE_VALIDATED, E, U),
    (RuleId.PY_WL_003, TaintState.UNKNOWN_SEM_VALIDATED, E, U),
    (RuleId.PY_WL_003, TaintState.MIXED_RAW, E, St),

    # PY-WL-004 = WL-003 (catching all exceptions broadly)
    (RuleId.PY_WL_004, TaintState.AUDIT_TRAIL, E, U),
    (RuleId.PY_WL_004, TaintState.PIPELINE, E, St),
    (RuleId.PY_WL_004, TaintState.SHAPE_VALIDATED, W, St),
    (RuleId.PY_WL_004, TaintState.EXTERNAL_RAW, W, R),
    (RuleId.PY_WL_004, TaintState.UNKNOWN_RAW, E, St),
    (RuleId.PY_WL_004, TaintState.UNKNOWN_SHAPE_VALIDATED, W, St),
    (RuleId.PY_WL_004, TaintState.UNKNOWN_SEM_VALIDATED, W, St),
    (RuleId.PY_WL_004, TaintState.MIXED_RAW, E, St),

    # PY-WL-005 = WL-004 (catching exceptions silently)
    (RuleId.PY_WL_005, TaintState.AUDIT_TRAIL, E, U),
    (RuleId.PY_WL_005, TaintState.PIPELINE, E, St),
    (RuleId.PY_WL_005, TaintState.SHAPE_VALIDATED, E, St),
    (RuleId.PY_WL_005, TaintState.EXTERNAL_RAW, E, St),
    (RuleId.PY_WL_005, TaintState.UNKNOWN_RAW, E, St),
    (RuleId.PY_WL_005, TaintState.UNKNOWN_SHAPE_VALIDATED, E, St),
    (RuleId.PY_WL_005, TaintState.UNKNOWN_SEM_VALIDATED, E, St),
    (RuleId.PY_WL_005, TaintState.MIXED_RAW, E, St),

    # PY-WL-006 = WL-005 (audit-critical writes in broad handlers)
    (RuleId.PY_WL_006, TaintState.AUDIT_TRAIL, E, U),
    (RuleId.PY_WL_006, TaintState.PIPELINE, E, U),
    (RuleId.PY_WL_006, TaintState.SHAPE_VALIDATED, E, St),
    (RuleId.PY_WL_006, TaintState.EXTERNAL_RAW, E, St),
    (RuleId.PY_WL_006, TaintState.UNKNOWN_RAW, E, St),
    (RuleId.PY_WL_006, TaintState.UNKNOWN_SHAPE_VALIDATED, E, St),
    (RuleId.PY_WL_006, TaintState.UNKNOWN_SEM_VALIDATED, E, St),
    (RuleId.PY_WL_006, TaintState.MIXED_RAW, E, St),

    # PY-WL-007 = WL-006 (runtime type-checking internal data)
    (RuleId.PY_WL_007, TaintState.AUDIT_TRAIL, E, St),
    (RuleId.PY_WL_007, TaintState.PIPELINE, W, R),
    (RuleId.PY_WL_007, TaintState.SHAPE_VALIDATED, W, R),
    (RuleId.PY_WL_007, TaintState.EXTERNAL_RAW, Su, T),
    (RuleId.PY_WL_007, TaintState.UNKNOWN_RAW, Su, T),
    (RuleId.PY_WL_007, TaintState.UNKNOWN_SHAPE_VALIDATED, W, R),
    (RuleId.PY_WL_007, TaintState.UNKNOWN_SEM_VALIDATED, W, R),
    (RuleId.PY_WL_007, TaintState.MIXED_RAW, W, St),

    # PY-WL-008 = WL-007 (validation with no rejection path)
    (RuleId.PY_WL_008, TaintState.AUDIT_TRAIL, E, U),
    (RuleId.PY_WL_008, TaintState.PIPELINE, E, U),
    (RuleId.PY_WL_008, TaintState.SHAPE_VALIDATED, E, U),
    (RuleId.PY_WL_008, TaintState.EXTERNAL_RAW, E, U),
    (RuleId.PY_WL_008, TaintState.UNKNOWN_RAW, E, U),
    (RuleId.PY_WL_008, TaintState.UNKNOWN_SHAPE_VALIDATED, E, U),
    (RuleId.PY_WL_008, TaintState.UNKNOWN_SEM_VALIDATED, E, U),
    (RuleId.PY_WL_008, TaintState.MIXED_RAW, E, U),

    # PY-WL-009 = WL-008 (semantic validation without shape validation)
    (RuleId.PY_WL_009, TaintState.AUDIT_TRAIL, E, U),
    (RuleId.PY_WL_009, TaintState.PIPELINE, E, U),
    (RuleId.PY_WL_009, TaintState.SHAPE_VALIDATED, E, U),
    (RuleId.PY_WL_009, TaintState.EXTERNAL_RAW, E, U),
    (RuleId.PY_WL_009, TaintState.UNKNOWN_RAW, E, U),
    (RuleId.PY_WL_009, TaintState.UNKNOWN_SHAPE_VALIDATED, E, U),
    (RuleId.PY_WL_009, TaintState.UNKNOWN_SEM_VALIDATED, E, U),
    (RuleId.PY_WL_009, TaintState.MIXED_RAW, E, U),
]
# fmt: on


def test_fixture_has_72_cells() -> None:
    assert len(EXPECTED) == 72


@pytest.mark.parametrize(
    ("rule", "taint", "exp_sev", "exp_exc"),
    EXPECTED,
    ids=lambda x: x.value if hasattr(x, "value") else str(x),
)
def test_matrix_cell(
    rule: RuleId,
    taint: TaintState,
    exp_sev: Severity,
    exp_exc: Exceptionability,
) -> None:
    # Import here to keep the fixture independent at module level
    from wardline.core.matrix import lookup

    cell = lookup(rule, taint)
    assert cell.severity is exp_sev, (
        f"{rule}×{taint}: expected severity {exp_sev}, got {cell.severity}"
    )
    assert cell.exceptionability is exp_exc, (
        f"{rule}×{taint}: expected exceptionability {exp_exc}, "
        f"got {cell.exceptionability}"
    )


def test_lookup_raises_on_invalid_combo() -> None:
    from wardline.core.matrix import lookup

    with pytest.raises(KeyError):
        lookup(RuleId.TOOL_ERROR, TaintState.AUDIT_TRAIL)


def test_no_matrix_import_at_module_level() -> None:
    """Verify this test file does not import from wardline.core.matrix at module level."""
    import ast
    from pathlib import Path

    source = Path(__file__).read_text()
    tree = ast.parse(source)
    # Check only top-level statements, not function bodies
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module:
            assert "matrix" not in node.module, (
                f"Module-level import of matrix found: {ast.dump(node)}"
            )
