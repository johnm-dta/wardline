"""Tests for Group 7 template-safety decorators."""

from __future__ import annotations

from wardline.decorators.safety import parse_at_init


class TestParseAtInit:
    """@parse_at_init decorator behaviour."""

    def test_sets_parse_at_init_attr(self) -> None:
        @parse_at_init
        def f() -> int:
            return 1

        assert f._wardline_parse_at_init is True  # type: ignore[attr-defined]

    def test_sets_group_7(self) -> None:
        @parse_at_init
        def f() -> int:
            return 1

        assert 7 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @parse_at_init
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @parse_at_init
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"
