"""wardline.runtime — Runtime support: base class, descriptors, type markers."""

from wardline.runtime.base import WardlineBase
from wardline.runtime.descriptors import AuthoritativeAccessError, AuthoritativeField
from wardline.runtime.enforcement import (
    TierViolationError,
    check_tier_boundary,
    check_validated_record,
)
from wardline.runtime.protocols import ValidatedRecord
from wardline.runtime.types import (
    TIER_REGISTRY,
    FailFast,
    Tier1,
    Tier2,
    Tier3,
    Tier4,
    TierMarker,
)

__all__ = [
    "AuthoritativeAccessError",
    "AuthoritativeField",
    "FailFast",
    "TIER_REGISTRY",
    "Tier1",
    "Tier2",
    "Tier3",
    "Tier4",
    "TierMarker",
    "TierViolationError",
    "ValidatedRecord",
    "WardlineBase",
    "check_tier_boundary",
    "check_validated_record",
]
