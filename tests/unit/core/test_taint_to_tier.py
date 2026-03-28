"""Tests for TAINT_TO_TIER mapping in wardline.core.tiers."""

import pytest

from wardline.core.taints import TaintState
from wardline.core.tiers import TAINT_TO_TIER, AuthorityTier


class TestTaintToTierCoversAllStates:
    """Completeness and per-entry correctness."""

    def test_taint_to_tier_covers_all_states(self) -> None:
        # Completeness: every TaintState member is a key
        assert set(TAINT_TO_TIER.keys()) == set(TaintState)

        # Per-entry correctness
        assert TAINT_TO_TIER[TaintState.INTEGRAL] == AuthorityTier.TIER_1
        assert TAINT_TO_TIER[TaintState.ASSURED] == AuthorityTier.TIER_2
        assert TAINT_TO_TIER[TaintState.GUARDED] == AuthorityTier.TIER_3
        assert TAINT_TO_TIER[TaintState.UNKNOWN_ASSURED] == AuthorityTier.TIER_3
        assert TAINT_TO_TIER[TaintState.UNKNOWN_GUARDED] == AuthorityTier.TIER_3
        assert TAINT_TO_TIER[TaintState.EXTERNAL_RAW] == AuthorityTier.TIER_4
        assert TAINT_TO_TIER[TaintState.UNKNOWN_RAW] == AuthorityTier.TIER_4
        assert TAINT_TO_TIER[TaintState.MIXED_RAW] == AuthorityTier.TIER_4


class TestTaintToTierFrozen:
    """MappingProxyType prevents mutation."""

    def test_taint_to_tier_frozen(self) -> None:
        with pytest.raises(TypeError):
            TAINT_TO_TIER[TaintState.INTEGRAL] = AuthorityTier.TIER_4  # type: ignore[index]

        with pytest.raises(TypeError):
            TAINT_TO_TIER[TaintState.MIXED_RAW] = AuthorityTier.TIER_1  # type: ignore[index]
