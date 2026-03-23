"""Tests for Group 12 concurrency decorators."""

from __future__ import annotations

from wardline.decorators.concurrency import process_safe, thread_safe


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

        assert 12 in f._wardline_groups  # type: ignore[attr-defined]

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


class TestProcessSafe:
    """@process_safe decorator behaviour."""

    def test_sets_process_safe_attr(self) -> None:
        @process_safe
        def f() -> int:
            return 1

        assert f._wardline_process_safe is True  # type: ignore[attr-defined]

    def test_sets_group_12(self) -> None:
        @process_safe
        def f() -> int:
            return 1

        assert 12 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @process_safe
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @process_safe
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"
