"""Call-graph taint utilities — trust order and least_trusted().

Part of the L3 call-graph taint propagation system (WP 2.1).
"""

from __future__ import annotations

from wardline.core.taints import TaintState

TRUST_RANK: dict[TaintState, int] = {
    TaintState.AUDIT_TRAIL: 0,
    TaintState.PIPELINE: 1,
    TaintState.SHAPE_VALIDATED: 2,
    TaintState.UNKNOWN_SEM_VALIDATED: 3,
    TaintState.UNKNOWN_SHAPE_VALIDATED: 4,
    TaintState.EXTERNAL_RAW: 5,
    TaintState.UNKNOWN_RAW: 6,
    TaintState.MIXED_RAW: 7,
}

# Use explicit check, not assert (survives Python -O)
if len(TRUST_RANK) != len(TaintState):
    raise ValueError(f"TRUST_RANK covers {len(TRUST_RANK)} states but TaintState has {len(TaintState)}")


def least_trusted(a: TaintState, b: TaintState) -> TaintState:
    """Return the less-trusted of two taint states (higher rank)."""
    return a if TRUST_RANK[a] >= TRUST_RANK[b] else b
