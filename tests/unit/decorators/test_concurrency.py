"""Tests for Group 13 concurrency decorators."""

from __future__ import annotations

from wardline.decorators.concurrency import not_reentrant, ordered_after, thread_safe


class TestThreadSafe:
    """@thread_safe decorator behaviour."""

    def test_sets_thread_safe_attr(self) -> None:
        @thread_safe
        def f() -> int:
            return 1

        assert f._wardline_thread_safe is True  # type: ignore[attr-defined]

    def test_sets_group_12(self) -> None:
        @thread_safe
        def f() -> int:
            return 1

        assert 13 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @thread_safe
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @thread_safe
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"


class TestOrderedAfter:
    """@ordered_after decorator behaviour."""

    def test_sets_ordered_after_attr(self) -> None:
        @ordered_after("bootstrap")
        def f() -> int:
            return 1

        assert f._wardline_ordered_after == "bootstrap"  # type: ignore[attr-defined]

    def test_sets_group_13(self) -> None:
        @ordered_after("bootstrap")
        def f() -> int:
            return 1

        assert 13 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @ordered_after("bootstrap")
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @ordered_after("bootstrap")
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"


class TestNotReentrant:
    """@not_reentrant decorator behaviour."""

    def test_sets_not_reentrant_attr(self) -> None:
        @not_reentrant
        def f() -> int:
            return 1

        assert f._wardline_not_reentrant is True  # type: ignore[attr-defined]

    def test_sets_group_13(self) -> None:
        @not_reentrant
        def f() -> int:
            return 1

        assert 13 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @not_reentrant
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @not_reentrant
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"
