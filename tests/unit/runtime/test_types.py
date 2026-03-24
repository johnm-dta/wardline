"""Tests for runtime type markers — TierMarker, Tier1-Tier4 (NewType), FailFast, TIER_REGISTRY."""

from __future__ import annotations

from types import MappingProxyType
from typing import Annotated, get_args

import pytest

from wardline.core.tiers import AuthorityTier
from wardline.runtime.types import (
    TIER_REGISTRY,
    FailFast,
    Tier1,
    Tier2,
    Tier3,
    Tier4,
    TierMarker,
    _FailFastMarker,
)


class TestTierMarker:
    """TierMarker construction and properties."""

    def test_valid_construction(self) -> None:
        for tier in (1, 2, 3, 4):
            marker = TierMarker(tier)
            assert marker.tier == AuthorityTier(tier)

    def test_invalid_tier_raises(self) -> None:
        with pytest.raises(ValueError, match="tier must be 1-4"):
            TierMarker(0)
        with pytest.raises(ValueError, match="tier must be 1-4"):
            TierMarker(5)

    def test_repr(self) -> None:
        marker = TierMarker(1)
        assert "TierMarker" in repr(marker)
        assert "1" in repr(marker)

    def test_equality(self) -> None:
        assert TierMarker(1) == TierMarker(1)
        assert TierMarker(1) != TierMarker(2)

    def test_hash(self) -> None:
        assert hash(TierMarker(1)) == hash(TierMarker(1))
        assert hash(TierMarker(1)) != hash(TierMarker(2))


class TestNewTypeTiers:
    """Tier1-Tier4 are NewType wrappers giving mypy tier-mismatch detection."""

    @pytest.mark.parametrize(
        "tier_type,name",
        [(Tier1, "Tier1"), (Tier2, "Tier2"), (Tier3, "Tier3"), (Tier4, "Tier4")],
    )
    def test_newtype_callable(self, tier_type: type, name: str) -> None:
        """Each TierN is callable (NewType constructor) and returns its argument."""
        value = tier_type("test_value")
        assert value == "test_value"

    @pytest.mark.parametrize(
        "tier_type,name",
        [(Tier1, "Tier1"), (Tier2, "Tier2"), (Tier3, "Tier3"), (Tier4, "Tier4")],
    )
    def test_newtype_supertype(self, tier_type: type, name: str) -> None:
        """Each TierN has __supertype__ == object (NewType base)."""
        assert tier_type.__supertype__ is object

    def test_tiers_are_distinct(self) -> None:
        """Each tier is a distinct type (not aliases of each other)."""
        assert Tier1 is not Tier2
        assert Tier2 is not Tier3
        assert Tier3 is not Tier4

    def test_usable_as_bare_annotation(self) -> None:
        """NewType tiers can be used as annotations."""
        x: Tier1 = Tier1("some value")  # type: ignore[assignment]
        assert x == "some value"


class TestTierRegistry:
    """TIER_REGISTRY maps tier type names to TierMarker instances."""

    def test_registry_has_all_four_tiers(self) -> None:
        assert len(TIER_REGISTRY) == 4
        for name in ("Tier1", "Tier2", "Tier3", "Tier4"):
            assert name in TIER_REGISTRY

    def test_registry_values_are_tier_markers(self) -> None:
        for _name, marker in TIER_REGISTRY.items():
            assert isinstance(marker, TierMarker)

    @pytest.mark.parametrize(
        "name,expected_tier",
        [("Tier1", 1), ("Tier2", 2), ("Tier3", 3), ("Tier4", 4)],
    )
    def test_registry_tier_values(self, name: str, expected_tier: int) -> None:
        assert TIER_REGISTRY[name].tier == AuthorityTier(expected_tier)

    def test_registry_is_frozen(self) -> None:
        assert isinstance(TIER_REGISTRY, MappingProxyType)
        with pytest.raises(TypeError):
            TIER_REGISTRY["Tier5"] = TierMarker(1)  # type: ignore[index]


class TestFailFast:
    """FailFast annotation marker."""

    def test_is_instance(self) -> None:
        assert isinstance(FailFast, _FailFastMarker)

    def test_repr(self) -> None:
        assert repr(FailFast) == "FailFast"

    def test_equality(self) -> None:
        other = _FailFastMarker()
        assert FailFast == other

    def test_usable_as_annotation(self) -> None:
        """FailFast can be used inside Annotated."""
        hint = Annotated[str, FailFast]
        args = get_args(hint)
        assert args[0] is str
        assert args[1] is FailFast
