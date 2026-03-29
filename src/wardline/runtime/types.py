"""Runtime type markers — NewType tier types for static type checking.

Provides ``Tier1`` through ``Tier4`` as ``NewType`` wrappers over
``object``, giving mypy native tier-mismatch detection without a
custom plugin::

    from wardline.runtime.types import Tier1, Tier4

    def process(raw: Tier4, validated: Tier1) -> None:
        ...

    # mypy error: Argument 1 has incompatible type "Tier4"; expected "Tier1"
    process(raw=fetch_external(), validated=fetch_external())

``Tier1(value)`` is an explicit trust boundary crossing — visible in
code review. The ``TIER_REGISTRY`` maps each NewType back to its
``TierMarker`` for runtime introspection.

Also provides ``FailFast``, a marker annotation indicating that a
function should abort immediately on authority violations rather than
accumulating findings.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import NewType

from wardline.core.tiers import AuthorityTier


class TierMarker:
    """Runtime metadata carrier for authority tier levels.

    Used in ``TIER_REGISTRY`` to map ``NewType`` tier types back to
    their tier level for runtime introspection (since ``NewType`` is
    erased at runtime).

    Immutable after construction — ``__setattr__`` and ``__delattr__``
    raise ``AttributeError`` to prevent mutation.

    Args:
        tier: The authority tier (1-4).
    """

    __slots__ = ("tier",)
    tier: AuthorityTier

    def __init__(self, tier: int) -> None:
        if tier not in (1, 2, 3, 4):
            raise ValueError(f"tier must be 1-4, got {tier}")
        object.__setattr__(self, "tier", AuthorityTier(tier))

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("TierMarker instances are immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("TierMarker instances are immutable")

    def __repr__(self) -> str:
        return f"TierMarker(tier={self.tier!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TierMarker):
            return NotImplemented
        return self.tier == other.tier

    def __hash__(self) -> int:
        return hash(self.tier)


class _FailFastMarker:
    """Annotation marker for fail-fast authority violation handling.

    Singleton marker — use the ``FailFast`` instance, not this class.
    """

    __slots__ = ()
    _instance: _FailFastMarker | None = None  # class var, not in __slots__

    def __new__(cls) -> _FailFastMarker:
        if cls._instance is None:
            cls._instance = object.__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "FailFast"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, _FailFastMarker):
            return NotImplemented
        return True

    def __hash__(self) -> int:
        return hash("FailFast")


# ── Public NewType tier types ─────────────────────────────────
#
# Each TierN is a distinct nominal type. mypy treats assignments between
# different tiers as type errors without any plugin:
#
#   x: Tier1 = Tier4(raw_data)  # mypy error
#   y: Tier1 = Tier1(validated) # ok — explicit trust boundary crossing
#
# Tier1(value) is a no-op at runtime (NewType is erased) but serves as
# a visible trust boundary marker in code.

Tier1 = NewType("Tier1", object)
Tier2 = NewType("Tier2", object)
Tier3 = NewType("Tier3", object)
Tier4 = NewType("Tier4", object)

# ── Tier registry for runtime introspection ───────────────────
#
# NewType erases at runtime, so code that needs to know "which tier
# does this type represent?" uses this registry. Frozen to prevent
# post-construction mutation.

TIER_REGISTRY: MappingProxyType[str, TierMarker] = MappingProxyType({
    "Tier1": TierMarker(1),
    "Tier2": TierMarker(2),
    "Tier3": TierMarker(3),
    "Tier4": TierMarker(4),
})

FailFast = _FailFastMarker()
