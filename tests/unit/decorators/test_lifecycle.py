"""Tests for Group 14 lifecycle decorators."""

from __future__ import annotations

from wardline.decorators.lifecycle import deprecated_boundary, experimental


class TestDeprecatedBoundary:
    """@deprecated_boundary decorator behaviour."""

    def test_sets_deprecated_boundary_attr(self) -> None:
        @deprecated_boundary
        def f() -> int:
            return 1

        assert f._wardline_deprecated_boundary is True  # type: ignore[attr-defined]

    def test_sets_group_14(self) -> None:
        @deprecated_boundary
        def f() -> int:
            return 1

        assert 14 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @deprecated_boundary
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @deprecated_boundary
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"


class TestExperimental:
    """@experimental decorator behaviour."""

    def test_sets_experimental_attr(self) -> None:
        @experimental
        def f() -> int:
            return 1

        assert f._wardline_experimental is True  # type: ignore[attr-defined]

    def test_sets_group_14(self) -> None:
        @experimental
        def f() -> int:
            return 1

        assert 14 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @experimental
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @experimental
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"
