"""Tests for AuthorityTier enum."""

import json

from wardline.core.tiers import AuthorityTier


def test_tier_values() -> None:
    assert AuthorityTier.TIER_1 == 1
    assert AuthorityTier.TIER_2 == 2
    assert AuthorityTier.TIER_3 == 3
    assert AuthorityTier.TIER_4 == 4


def test_tier_count() -> None:
    assert len(AuthorityTier) == 4


def test_tier_json_serialisation() -> None:
    """IntEnum members serialise as integers via json.dumps."""
    assert json.dumps(AuthorityTier.TIER_1) == "1"
    assert json.dumps(AuthorityTier.TIER_4) == "4"


def test_tier_ordering_and_comparison_operators() -> None:
    """IntEnum members compare using their numeric tier values."""
    assert AuthorityTier.TIER_1 < AuthorityTier.TIER_2
    assert AuthorityTier.TIER_2 <= AuthorityTier.TIER_2
    assert AuthorityTier.TIER_3 > AuthorityTier.TIER_2
    assert AuthorityTier.TIER_4 >= AuthorityTier.TIER_3


def test_is_more_authoritative_than_uses_domain_semantics() -> None:
    assert AuthorityTier.TIER_1.is_more_authoritative_than(AuthorityTier.TIER_2)
    assert AuthorityTier.TIER_2.is_more_authoritative_than(AuthorityTier.TIER_4)
    assert not AuthorityTier.TIER_4.is_more_authoritative_than(AuthorityTier.TIER_1)
    assert not AuthorityTier.TIER_3.is_more_authoritative_than(AuthorityTier.TIER_3)
