"""Tests for Group 15 lifecycle decorators."""

from __future__ import annotations

from wardline.decorators.lifecycle import deprecated_by, feature_gated
from wardline.decorators.lifecycle import test_only as only_decorator


class TestTestOnly:
    """@test_only decorator behaviour."""

    def test_sets_test_only_attr(self) -> None:
        @only_decorator
        def f() -> int:
            return 1

        assert f._wardline_test_only is True  # type: ignore[attr-defined]

    def test_sets_group_15(self) -> None:
        @only_decorator
        def f() -> int:
            return 1

        assert 15 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @only_decorator
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @only_decorator
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"


class TestDeprecatedBy:
    """@deprecated_by decorator behaviour."""

    def test_sets_deprecated_by_attrs(self) -> None:
        @deprecated_by(date="2026-12-31", replacement="new_api")
        def f() -> int:
            return 1

        assert f._wardline_deprecated_by is True  # type: ignore[attr-defined]
        assert f._wardline_deprecation_date == "2026-12-31"  # type: ignore[attr-defined]
        assert f._wardline_replacement == "new_api"  # type: ignore[attr-defined]

    def test_sets_group_15(self) -> None:
        @deprecated_by(date="2026-12-31", replacement="new_api")
        def f() -> int:
            return 1

        assert 15 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @deprecated_by(date="2026-12-31", replacement="new_api")
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @deprecated_by(date="2026-12-31", replacement="new_api")
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"


class TestFeatureGated:
    """@feature_gated decorator behaviour."""

    def test_sets_feature_gated_attrs(self) -> None:
        @feature_gated(flag="beta")
        def f() -> int:
            return 1

        assert f._wardline_feature_gated is True  # type: ignore[attr-defined]
        assert f._wardline_feature_flag == "beta"  # type: ignore[attr-defined]

    def test_sets_group_15(self) -> None:
        @feature_gated(flag="beta")
        def f() -> int:
            return 1

        assert 15 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @feature_gated(flag="beta")
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @feature_gated(flag="beta")
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"
