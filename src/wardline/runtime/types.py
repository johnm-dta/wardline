"""Runtime type markers — Annotated aliases for tier-aware type hints.

Provides ``Tier1`` through ``Tier4`` as ``Annotated[Any, TierMarker(N)]``
aliases, allowing user code to annotate variables and parameters with
their expected authority tier::

    from wardline.runtime.types import Tier1, Tier4

    def process(raw: Tier4, validated: Tier1) -> None:
        ...

Also provides ``FailFast``, a marker annotation indicating that a
function should abort immediately on authority violations rather than
accumulating findings.
"""

from __future__ import annotations

from typing import Annotated, Any

from wardline.core.tiers import AuthorityTier


class TierMarker:
    """Annotation marker carrying an authority tier level.

    Used inside ``Annotated`` to attach tier metadata to a type hint
    without altering the runtime type.

    Args:
        tier: The authority tier (1-4).
    """

    __slots__ = ("tier",)

    def __init__(self, tier: int) -> None:
        if tier not in (1, 2, 3, 4):
            raise ValueError(f"tier must be 1-4, got {tier}")
        self.tier = AuthorityTier(tier)

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

    def __repr__(self) -> str:
        return "FailFast"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _FailFastMarker)

    def __hash__(self) -> int:
        return hash("FailFast")


# ── Public Annotated aliases ──────────────────────────────────

type Tier1 = Annotated[Any, TierMarker(1)]
type Tier2 = Annotated[Any, TierMarker(2)]
type Tier3 = Annotated[Any, TierMarker(3)]
type Tier4 = Annotated[Any, TierMarker(4)]

FailFast = _FailFastMarker()
