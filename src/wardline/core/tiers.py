"""Authority tier model — four-tier trust hierarchy."""

from enum import IntEnum
from types import MappingProxyType

from wardline.core.taints import TaintState


class AuthorityTier(IntEnum):
    """Authority tier levels (1 = highest authority, 4 = untrusted)."""

    TIER_1 = 1
    TIER_2 = 2
    TIER_3 = 3
    TIER_4 = 4


TAINT_TO_TIER: MappingProxyType[TaintState, AuthorityTier] = MappingProxyType({
    TaintState.AUDIT_TRAIL: AuthorityTier.TIER_1,
    TaintState.PIPELINE: AuthorityTier.TIER_2,
    TaintState.SHAPE_VALIDATED: AuthorityTier.TIER_3,
    TaintState.UNKNOWN_SEM_VALIDATED: AuthorityTier.TIER_3,
    TaintState.UNKNOWN_SHAPE_VALIDATED: AuthorityTier.TIER_3,
    TaintState.EXTERNAL_RAW: AuthorityTier.TIER_4,
    TaintState.UNKNOWN_RAW: AuthorityTier.TIER_4,
    TaintState.MIXED_RAW: AuthorityTier.TIER_4,
})

# Explicit check (not assert — survives python -O)
missing = set(TaintState) - TAINT_TO_TIER.keys()
if missing:
    raise ValueError(f"TAINT_TO_TIER missing entries for: {missing}")
