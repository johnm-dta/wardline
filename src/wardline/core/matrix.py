"""Severity matrix — 72 cells mapping (rule, taint) to (severity, exceptionability)."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.core.taints import TaintState

_E = Severity.ERROR
_W = Severity.WARNING
_Su = Severity.SUPPRESS

_U = Exceptionability.UNCONDITIONAL
_St = Exceptionability.STANDARD
_R = Exceptionability.RELAXED
_T = Exceptionability.TRANSPARENT


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
    (RuleId.PY_WL_001, [(_E,_U), (_E,_St), (_E,_St), (_E,_St), (_E,_St), (_E,_St), (_E,_St), (_E,_St)]),
    # PY-WL-002 inherits WL-001 matrix (attribute access with fallback default)
    (RuleId.PY_WL_002, [(_E,_U), (_E,_St), (_E,_St), (_E,_St), (_E,_St), (_E,_St), (_E,_St), (_E,_St)]),
    # PY-WL-003 = WL-002 (existence-checking as structural gate)
    (RuleId.PY_WL_003, [(_E,_U), (_E,_U), (_E,_U), (_E,_St), (_E,_St), (_E,_U), (_E,_U), (_E,_St)]),
    # PY-WL-004 = WL-003 (catching all exceptions broadly)
    (RuleId.PY_WL_004, [(_E,_U), (_E,_St), (_W,_St), (_W,_R), (_E,_St), (_W,_St), (_W,_St), (_E,_St)]),
    # PY-WL-005 = WL-004 (catching exceptions silently)
    (RuleId.PY_WL_005, [(_E,_U), (_E,_St), (_E,_St), (_E,_St), (_E,_St), (_E,_St), (_E,_St), (_E,_St)]),
    # PY-WL-006 = WL-005 (audit-critical writes in broad handlers)
    (RuleId.PY_WL_006, [(_E,_U), (_E,_U), (_E,_St), (_E,_St), (_E,_St), (_E,_St), (_E,_St), (_E,_St)]),
    # PY-WL-007 = WL-006 (runtime type-checking internal data)
    (RuleId.PY_WL_007, [(_E,_St), (_W,_R), (_W,_R), (_Su,_T), (_Su,_T), (_W,_R), (_W,_R), (_W,_St)]),
    # PY-WL-008 = WL-007 (validation with no rejection path)
    (RuleId.PY_WL_008, [(_E,_U), (_E,_U), (_E,_U), (_E,_U), (_E,_U), (_E,_U), (_E,_U), (_E,_U)]),
    # PY-WL-009 = WL-008 (semantic validation without shape validation)
    (RuleId.PY_WL_009, [(_E,_U), (_E,_U), (_E,_U), (_E,_U), (_E,_U), (_E,_U), (_E,_U), (_E,_U)]),
]
# fmt: on

_severity_matrix_builder: dict[tuple[RuleId, TaintState], SeverityCell] = {}
for _rule, _cells in _MATRIX_DATA:
    for _taint, (_sev, _exc) in zip(_TAINT_ORDER, _cells, strict=True):
        _severity_matrix_builder[(_rule, _taint)] = SeverityCell(
            severity=_sev, exceptionability=_exc
        )

# Completeness check: every canonical rule must have all 8 taint entries.
_EXPECTED_RULES = frozenset(r for r, _ in _MATRIX_DATA)
_EXPECTED_COUNT = len(_EXPECTED_RULES) * len(_TAINT_ORDER)
if len(_severity_matrix_builder) != _EXPECTED_COUNT:
    raise ValueError(
        f"Severity matrix incomplete: expected {_EXPECTED_COUNT} cells "
        f"({len(_EXPECTED_RULES)} rules × {len(_TAINT_ORDER)} taints), "
        f"got {len(_severity_matrix_builder)}"
    )
del _EXPECTED_RULES, _EXPECTED_COUNT

SEVERITY_MATRIX: MappingProxyType[tuple[RuleId, TaintState], SeverityCell] = (
    MappingProxyType(_severity_matrix_builder)
)
del _severity_matrix_builder


def lookup(rule: RuleId, taint: TaintState) -> SeverityCell:
    """Look up the severity cell for a (rule, taint) pair.

    Raises KeyError if the combination is not in the matrix
    (e.g., pseudo-rule-IDs are not analysis rules).
    """
    try:
        return SEVERITY_MATRIX[(rule, taint)]
    except KeyError:
        raise KeyError(
            f"No severity-matrix entry for ({rule!r}, {taint!r}). "
            f"Only canonical analysis rules (PY-WL-001..009) have matrix "
            f"entries — pseudo-rule-IDs and unmapped taint states are not "
            f"in the matrix."
        ) from None
