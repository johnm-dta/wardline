"""Authority tier model — four-tier trust hierarchy."""

from enum import IntEnum


class AuthorityTier(IntEnum):
    """Authority tier levels (1 = highest authority, 4 = untrusted)."""

    TIER_1 = 1
    TIER_2 = 2
    TIER_3 = 3
    TIER_4 = 4
