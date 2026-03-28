"""Tests for @restoration_boundary decorator (Group 17)."""
from __future__ import annotations

import asyncio

import pytest

from wardline.decorators.provenance import int_data
from wardline.decorators.restoration import restoration_boundary


class TestRestorationBoundary:
    """@restoration_boundary decorator behaviour."""

    def test_sets_all_attrs(self) -> None:
        @restoration_boundary(
            restored_tier=1,
            structural_evidence=True,
            semantic_evidence=True,
            integrity_evidence="hmac",
            institutional_provenance="org-db",
        )
        def restore(raw: bytes) -> object: ...

        assert restore._wardline_restoration_boundary is True
        assert restore._wardline_restored_tier == 1
        assert restore._wardline_structural_evidence is True
        assert restore._wardline_semantic_evidence is True
        assert restore._wardline_integrity_evidence == "hmac"
        assert restore._wardline_institutional_provenance == "org-db"

    def test_optional_attrs_default_to_none(self) -> None:
        @restoration_boundary(restored_tier=3, structural_evidence=True)
        def restore(raw: bytes) -> object: ...

        assert restore._wardline_semantic_evidence is False
        assert restore._wardline_integrity_evidence is None
        assert restore._wardline_institutional_provenance is None

    def test_restored_tier_validated(self) -> None:
        with pytest.raises(ValueError, match="restored_tier must be 1-4"):
            restoration_boundary(restored_tier=0)
        with pytest.raises(ValueError, match="restored_tier must be 1-4"):
            restoration_boundary(restored_tier=5)

    def test_valid_tier_values(self) -> None:
        for tier in (1, 2, 3, 4):
            @restoration_boundary(restored_tier=tier, structural_evidence=True)
            def restore(raw: bytes) -> object: ...
            assert restore._wardline_restored_tier == tier

    def test_async_function(self) -> None:
        @restoration_boundary(restored_tier=2, structural_evidence=True)
        async def restore(raw: bytes) -> object:
            return object()
        assert asyncio.iscoroutinefunction(restore)
        assert restore._wardline_restoration_boundary is True

    def test_stacks_with_int_data_inner(self) -> None:
        @restoration_boundary(restored_tier=1, structural_evidence=True)
        @int_data
        def restore(raw: bytes) -> object: ...
        assert restore._wardline_restoration_boundary is True
        assert restore._wardline_int_data is True
        assert 4 in restore._wardline_groups
        assert 17 in restore._wardline_groups

    def test_stacks_with_int_data_outer(self) -> None:
        @int_data
        @restoration_boundary(restored_tier=1, structural_evidence=True)
        def restore(raw: bytes) -> object: ...
        assert restore._wardline_restoration_boundary is True
        assert restore._wardline_int_data is True
        assert 4 in restore._wardline_groups
        assert 17 in restore._wardline_groups

    def test_groups_accumulates(self) -> None:
        @restoration_boundary(restored_tier=2, structural_evidence=True)
        def restore(raw: bytes) -> object: ...
        assert 17 in restore._wardline_groups

    def test_no_runtime_tier_stamping(self) -> None:
        """_compute_output_tier returns None → no tier stamped on result."""
        @restoration_boundary(restored_tier=1, structural_evidence=True)
        def restore(raw: bytes) -> object:
            return {"data": "test"}
        result = restore(b"raw")
        assert not hasattr(result, "_wardline_tier")
