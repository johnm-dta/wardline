"""Taint state model — 8 canonical taint state tokens and join lattice."""

from __future__ import annotations

from enum import StrEnum


class TaintState(StrEnum):
    """Canonical taint states per spec §5.

    Values are explicit uppercase strings — do NOT use auto() which
    produces lowercase and would silently break SARIF output, matrix
    lookups, and corpus matching.
    """

    AUDIT_TRAIL = "AUDIT_TRAIL"
    PIPELINE = "PIPELINE"
    SHAPE_VALIDATED = "SHAPE_VALIDATED"
    EXTERNAL_RAW = "EXTERNAL_RAW"
    UNKNOWN_RAW = "UNKNOWN_RAW"
    UNKNOWN_SHAPE_VALIDATED = "UNKNOWN_SHAPE_VALIDATED"
    UNKNOWN_SEM_VALIDATED = "UNKNOWN_SEM_VALIDATED"
    MIXED_RAW = "MIXED_RAW"


# Non-trivial join pairs (upper triangle, excluding self-joins).
# Self-joins are handled via identity check: join(a, a) == a.
# Operand order is normalised for lookup: min(a, b), max(a, b) by value.
# All pairs not listed here produce MIXED_RAW.
_UR = TaintState.UNKNOWN_RAW
_USH = TaintState.UNKNOWN_SHAPE_VALIDATED
_USE = TaintState.UNKNOWN_SEM_VALIDATED

_JOIN_TABLE: dict[tuple[TaintState, TaintState], TaintState] = {
    # Within UNKNOWN family: demote to weaker validation.
    # Keys MUST be in normalized order (sorted by .value string) to match
    # the lookup normalization in taint_join().
    (_UR, _USE): _UR,
    (_UR, _USH): _UR,
    (_USE, _USH): _USH,
}


def taint_join(a: TaintState, b: TaintState) -> TaintState:
    """Compute the join of two taint states per spec §5.

    The join is commutative: join(a, b) == join(b, a).
    MIXED_RAW is the absorbing element: join(MIXED_RAW, X) == MIXED_RAW for all X.
    Self-joins are identity: join(a, a) == a.
    """
    if a == b:
        return a

    if a == TaintState.MIXED_RAW or b == TaintState.MIXED_RAW:
        return TaintState.MIXED_RAW

    # Normalise order for lookup (by string value for determinism)
    key = (min(a, b, key=lambda x: x.value), max(a, b, key=lambda x: x.value))
    if key in _JOIN_TABLE:
        return _JOIN_TABLE[key]
    # Pairs not in the join table collapse to the absorbing element.
    return TaintState.MIXED_RAW
