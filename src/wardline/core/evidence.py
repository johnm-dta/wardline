"""§5.3 evidence-to-tier matrix — pure domain function."""

from __future__ import annotations

from wardline.core.taints import TaintState


def max_restorable_tier(
    structural: bool,
    semantic: bool,
    integrity: bool,
    institutional: bool,
) -> TaintState:
    """Return the maximum tier evidence supports per §5.3.

    The caller coerces string evidence values to bool before calling:
    ``integrity_evidence="hmac"`` → ``integrity=True``,
    ``integrity_evidence=None`` → ``integrity=False``.

    Institutional evidence is the gate between known-provenance tiers
    (T1–T3) and unknown-provenance states (UNKNOWN_*).
    """
    if not structural:
        return TaintState.UNKNOWN_RAW
    if not institutional:
        if semantic:
            return TaintState.UNKNOWN_SEM_VALIDATED
        return TaintState.UNKNOWN_SHAPE_VALIDATED
    # institutional is True from here
    if semantic and integrity:
        return TaintState.AUDIT_TRAIL  # Tier 1
    if semantic:
        return TaintState.PIPELINE  # Tier 2
    return TaintState.SHAPE_VALIDATED  # Tier 3
