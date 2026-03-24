"""Tests for call-graph taint trust order and least_trusted()."""

from __future__ import annotations

from wardline.core.taints import TaintState
from wardline.scanner.taint.callgraph import TRUST_RANK, least_trusted


class TestTrustRank:
    def test_trust_rank_covers_all_states(self) -> None:
        """Every TaintState member has a rank in TRUST_RANK."""
        for state in TaintState:
            assert state in TRUST_RANK, f"{state} missing from TRUST_RANK"
        assert len(TRUST_RANK) == len(TaintState)


class TestLeastTrusted:
    def test_least_trusted_returns_less_trusted(self) -> None:
        """AUDIT_TRAIL vs EXTERNAL_RAW should return EXTERNAL_RAW."""
        result = least_trusted(TaintState.AUDIT_TRAIL, TaintState.EXTERNAL_RAW)
        assert result == TaintState.EXTERNAL_RAW

    def test_least_trusted_symmetric(self) -> None:
        """least_trusted(a, b) == least_trusted(b, a) for all 8x8 pairs."""
        for a in TaintState:
            for b in TaintState:
                assert least_trusted(a, b) == least_trusted(b, a), f"Not symmetric for ({a}, {b})"

    def test_least_trusted_identity(self) -> None:
        """least_trusted(a, a) == a for all states."""
        for state in TaintState:
            assert least_trusted(state, state) == state

    def test_mixed_raw_is_bottom(self) -> None:
        """MIXED_RAW vs any X should return MIXED_RAW (it is the least trusted)."""
        for state in TaintState:
            assert least_trusted(TaintState.MIXED_RAW, state) == TaintState.MIXED_RAW
            assert least_trusted(state, TaintState.MIXED_RAW) == TaintState.MIXED_RAW
