"""Tests for Group 9 operations decorators."""

from __future__ import annotations

from wardline.decorators.operations import idempotent, retry_safe


class TestIdempotent:
    """@idempotent decorator behaviour."""

    def test_sets_idempotent_attr(self) -> None:
        @idempotent
        def f() -> int:
            return 1

        assert f._wardline_idempotent is True  # type: ignore[attr-defined]

    def test_sets_group_9(self) -> None:
        @idempotent
        def f() -> int:
            return 1

        assert 9 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @idempotent
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @idempotent
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"


class TestRetrySafe:
    """@retry_safe decorator behaviour."""

    def test_sets_retry_safe_attr(self) -> None:
        @retry_safe
        def f() -> int:
            return 1

        assert f._wardline_retry_safe is True  # type: ignore[attr-defined]

    def test_sets_group_9(self) -> None:
        @retry_safe
        def f() -> int:
            return 1

        assert 9 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @retry_safe
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @retry_safe
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"
