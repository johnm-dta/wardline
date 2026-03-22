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
