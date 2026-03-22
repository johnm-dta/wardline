"""Tests for runtime type markers — TierMarker, Tier1-Tier4, FailFast."""

from __future__ import annotations

from typing import Annotated, Any, get_args

import pytest

from wardline.core.tiers import AuthorityTier
from wardline.runtime.types import (
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


class TestAnnotatedAliases:
    """Tier1-Tier4 are valid Annotated[Any, TierMarker(N)] aliases."""

    @pytest.mark.parametrize(
        "alias,expected_tier",
        [(Tier1, 1), (Tier2, 2), (Tier3, 3), (Tier4, 4)],
    )
    def test_annotated_structure(
        self, alias: type, expected_tier: int
    ) -> None:
        # Python 3.12 `type` statement produces TypeAliasType;
        # unwrap via __value__ to reach the underlying Annotated form.
        resolved = alias.__value__ if hasattr(alias, "__value__") else alias
        args = get_args(resolved)
        assert len(args) == 2
        assert args[0] is Any
        assert isinstance(args[1], TierMarker)
        assert args[1].tier == AuthorityTier(expected_tier)

    def test_usable_as_bare_annotation(self) -> None:
        """Tier aliases can be used as bare annotations."""
        # This should not raise — it's a valid type hint
        x: Tier1 = "some value"  # type: ignore[valid-type]
        assert x == "some value"


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
