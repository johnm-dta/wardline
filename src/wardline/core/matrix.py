"""Severity matrix — 72 cells mapping (rule, taint) to (severity, exceptionability)."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.core.taints import TaintState

E = Severity.ERROR
W = Severity.WARNING
Su = Severity.SUPPRESS

U = Exceptionability.UNCONDITIONAL
St = Exceptionability.STANDARD
R = Exceptionability.RELAXED
T = Exceptionability.TRANSPARENT


@dataclass(frozen=True)
class SeverityCell:
    """A single cell in the severity matrix."""

    severity: Severity
    exceptionability: Exceptionability


# Column order matches spec §7.3:
# AUDIT_TRAIL, PIPELINE, SHAPE_VALIDATED, EXTERNAL_RAW,
# UNKNOWN_RAW, UNKNOWN_SHAPE_VALIDATED, UNKNOWN_SEM_VALIDATED, MIXED_RAW
_TAINT_ORDER = [
    TaintState.AUDIT_TRAIL,
    TaintState.PIPELINE,
    TaintState.SHAPE_VALIDATED,
    TaintState.EXTERNAL_RAW,
    TaintState.UNKNOWN_RAW,
    TaintState.UNKNOWN_SHAPE_VALIDATED,
    TaintState.UNKNOWN_SEM_VALIDATED,
    TaintState.MIXED_RAW,
]

# fmt: off
# Row data: (rule, [(severity, exceptionability) for each taint state])
_MATRIX_DATA: list[tuple[RuleId, list[tuple[Severity, Exceptionability]]]] = [
    # PY-WL-001 inherits WL-001 matrix (dict key access with fallback default)
    (RuleId.PY_WL_001, [(E,U), (E,St), (E,St), (E,St), (E,St), (E,St), (E,St), (E,St)]),
    # PY-WL-002 inherits WL-001 matrix (attribute access with fallback default)
    (RuleId.PY_WL_002, [(E,U), (E,St), (E,St), (E,St), (E,St), (E,St), (E,St), (E,St)]),
    # PY-WL-003 = WL-002 (existence-checking as structural gate)
    (RuleId.PY_WL_003, [(E,U), (E,U), (E,U), (E,St), (E,St), (E,U), (E,U), (E,St)]),
    # PY-WL-004 = WL-003 (catching all exceptions broadly)
    (RuleId.PY_WL_004, [(E,U), (E,St), (W,St), (W,R), (E,St), (W,St), (W,St), (E,St)]),
    # PY-WL-005 = WL-004 (catching exceptions silently)
    (RuleId.PY_WL_005, [(E,U), (E,St), (E,St), (E,St), (E,St), (E,St), (E,St), (E,St)]),
    # PY-WL-006 = WL-005 (audit-critical writes in broad handlers)
    (RuleId.PY_WL_006, [(E,U), (E,U), (E,St), (E,St), (E,St), (E,St), (E,St), (E,St)]),
    # PY-WL-007 = WL-006 (runtime type-checking internal data)
    (RuleId.PY_WL_007, [(E,St), (W,R), (W,R), (Su,T), (Su,T), (W,R), (W,R), (W,St)]),
    # PY-WL-008 = WL-007 (validation with no rejection path)
    (RuleId.PY_WL_008, [(E,U), (E,U), (E,U), (E,U), (E,U), (E,U), (E,U), (E,U)]),
    # PY-WL-009 = WL-008 (semantic validation without shape validation)
    (RuleId.PY_WL_009, [(E,U), (E,U), (E,U), (E,U), (E,U), (E,U), (E,U), (E,U)]),
]
# fmt: on

_severity_matrix_builder: dict[tuple[RuleId, TaintState], SeverityCell] = {}
for _rule, _cells in _MATRIX_DATA:
    for _taint, (_sev, _exc) in zip(_TAINT_ORDER, _cells, strict=True):
        _severity_matrix_builder[(_rule, _taint)] = SeverityCell(
            severity=_sev, exceptionability=_exc
        )

SEVERITY_MATRIX: MappingProxyType[tuple[RuleId, TaintState], SeverityCell] = (
    MappingProxyType(_severity_matrix_builder)
)
del _severity_matrix_builder


def lookup(rule: RuleId, taint: TaintState) -> SeverityCell:
    """Look up the severity cell for a (rule, taint) pair.

    Raises KeyError if the combination is not in the matrix
    (e.g., pseudo-rule-IDs are not analysis rules).
    """
    return SEVERITY_MATRIX[(rule, taint)]
