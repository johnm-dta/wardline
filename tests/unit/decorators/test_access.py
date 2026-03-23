"""Tests for Group 13 access decorators."""

from __future__ import annotations

from wardline.decorators.access import requires_auth, requires_role


class TestRequiresAuth:
    """@requires_auth decorator behaviour."""

    def test_sets_requires_auth_attr(self) -> None:
        @requires_auth
        def f() -> int:
            return 1

        assert f._wardline_requires_auth is True  # type: ignore[attr-defined]

    def test_sets_group_13(self) -> None:
        @requires_auth
        def f() -> int:
            return 1

        assert 13 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @requires_auth
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @requires_auth
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"


class TestRequiresRole:
    """@requires_role decorator behaviour."""

    def test_sets_requires_role_attr(self) -> None:
        @requires_role
        def f() -> int:
            return 1

        assert f._wardline_requires_role is True  # type: ignore[attr-defined]

    def test_sets_group_13(self) -> None:
        @requires_role
        def f() -> int:
            return 1

        assert 13 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @requires_role
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @requires_role
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"
