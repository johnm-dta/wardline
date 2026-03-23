"""Tests for Group 6 boundary decorators."""

from __future__ import annotations

from wardline.decorators.boundaries import tier_transition, trust_boundary


class TestTrustBoundary:
    """@trust_boundary decorator behaviour."""

    def test_sets_trust_boundary_attr(self) -> None:
        @trust_boundary
        def f() -> int:
            return 1

        assert f._wardline_trust_boundary is True  # type: ignore[attr-defined]

    def test_sets_group_6(self) -> None:
        @trust_boundary
        def f() -> int:
            return 1

        assert 6 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @trust_boundary
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @trust_boundary
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"


class TestTierTransition:
    """@tier_transition decorator behaviour."""

    def test_sets_tier_transition_attr(self) -> None:
        @tier_transition
        def f() -> int:
            return 1

        assert f._wardline_tier_transition is True  # type: ignore[attr-defined]

    def test_sets_group_6(self) -> None:
        @tier_transition
        def f() -> int:
            return 1

        assert 6 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @tier_transition
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @tier_transition
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"
